#!/usr/bin/env python3
"""Check the adapter against pinned, real Android 5.10.236 source and SUSFS.

Requires Python 3 and GNU patch; downloads reference text into a temporary test
tree, creates no backups, and never reads or changes a user's AK3 image.
"""
import base64
import concurrent.futures
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

import legacy_susfs as adapter

COMMON_REV = "fbb4c9b0aa29"
LEGACY_REV = "c06d5f8ef2b53d04c5e1c6b86dc3076f1e0e9f33"


def download(url):
    with urllib.request.urlopen(url, timeout=45) as response:
        return response.read()


def base_source(path):
    url = f"https://android.googlesource.com/kernel/common/+/{COMMON_REV}/{path}?format=TEXT"
    return path, base64.b64decode(download(url)).decode("utf-8")


def fixture_sources(revision=adapter.SUSFS_REV, paths=adapter.PATHS):
    patch = shutil.which("patch")
    if not patch and os.name == "nt":
        candidate = Path("C:/Program Files/Git/usr/bin/patch.exe")
        if candidate.is_file():
            patch = str(candidate)
    if not patch:
        raise RuntimeError("GNU patch is required")
    patch_url = (f"https://raw.githubusercontent.com/ShirkNeko/susfs4ksu/{revision}"
                 "/kernel_patches/50_add_susfs_in_gki-android12-5.10.patch")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        future = pool.submit(download, patch_url)
        base = dict(pool.map(base_source, paths))
        patch_text = future.result().decode("utf-8")
    chunks = re.split(r"(?=^diff --git )", patch_text, flags=re.M)
    selected = []
    for path in paths:
        matches = [chunk for chunk in chunks if chunk.startswith(f"diff --git a/{path} b/{path}\n")]
        assert len(matches) == 1, (path, len(matches))
        selected.append(matches[0])
    with tempfile.TemporaryDirectory(prefix="susfs-source-test-") as folder:
        root = Path(folder)
        for path, source in base.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8", newline="\n")
        run = subprocess.run(
            [patch, "-p1", "--batch", "--forward", "--no-backup-if-mismatch"],
            input="".join(selected), cwd=root, text=True, encoding="utf-8",
            capture_output=True,
        )
        print("PATCH stdout:\n" + run.stdout.rstrip())
        print("PATCH stderr:\n" + run.stderr.rstrip())
        print("PATCH exit:", run.returncode)
        if run.returncode:
            raise RuntimeError("Pinned SUSFS did not apply completely to the real target source")
        return {path: (root / path).read_text(encoding="utf-8") for path in paths}


def body(source, function):
    match = re.search(r"\b" + re.escape(function) + r"\([^;{}]*\)\s*\{", source)
    assert match, function
    begin = match.end() - 1
    depth = 0
    for end in range(begin, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if depth == 0:
            return source[begin:end + 1]
    raise AssertionError("unterminated function " + function)


def check(sources):
    baseline_hashes = {p: hashlib.sha256(s.encode()).hexdigest() for p, s in sources.items()}
    for symbol in ("my_write_context", "my_write_access"):
        assert f"return {symbol}(" in sources[adapter.FS]
    assert "return my_setprocattr(" in sources[adapter.HOOKS]
    print("BASELINE: unresolved new SELinux backend calls present")
    changed = adapter.transform(sources)
    assert baseline_hashes == {p: hashlib.sha256(s.encode()).hexdigest() for p, s in sources.items()}
    hooks = body(changed[adapter.HOOKS], "selinux_setprocattr")
    assert hooks.index("PROCESS__SETCURRENT") < hooks.index("int fake_error =")
    assert hooks.index("int fake_error =") < hooks.index("security_context_to_sid(&selinux_state")
    assert hooks.index("security_context_to_sid(&selinux_state") < hooks.index("prepare_creds()")
    assert hooks.index("PROCESS__DYNTRANSITION") < hooks.index("commit_creds(new)")
    assert hooks.index("PROCESS__PTRACE") < hooks.index("commit_creds(new)")
    assert "tsec->sid = sid;" in hooks and "tsec->sid = tmp_sid" not in hooks
    for function, required in (
        ("sel_write_context", ("security_context_to_sid(&fake_state", "security_sid_to_context(&fake_state")),
        ("sel_write_access", ("security_context_str_to_sid(&fake_state, scon", "security_context_str_to_sid(&fake_state, tcon", "security_compute_av_user(&fake_state")),
    ):
        text = body(changed[adapter.FS], function)
        assert "current_uid().val >= 10000 && ksu_selinux_hide_running" in text
        for call in required:
            assert text.index("avc_has_perm(") < text.index(call)
        assert text.count("avc_has_perm(") == body(sources[adapter.FS], function).count("avc_has_perm(")
    assert body(sources[adapter.FS], "sel_open_handle_status") == body(changed[adapter.FS], "sel_open_handle_status")
    for path in adapter.SUCOMPAT_PATHS:
        assert "extern bool ksu_su_compat_enabled;" in changed[path]
        assert "READ_ONCE(ksu_su_compat_enabled)" in changed[path]
        assert "static_branch_likely(&ksu_su_compat_enabled)" not in changed[path]
    assert changed[adapter.EXEC].index("#define KSU_NO_PREINIT 1") < changed[adapter.EXEC].index("#ifndef KSU_NO_PREINIT")
    assert "(void)ksu_handle_sys_read(fd, &buf, &count);" in changed["fs/read_write.c"]
    assert "extern void ksu_handle_sys_read" not in changed["fs/read_write.c"]
    assert adapter.transform(changed) == changed
    drift = dict(sources)
    drift[adapter.FS] = drift[adapter.FS].replace("return my_write_access(file, buf, size);", "return changed_backend(file, buf, size);")
    try:
        adapter.transform(drift)
    except ValueError:
        pass
    else:
        raise AssertionError("Unexpected source drift must be rejected")
    partial = dict(sources)
    partial[adapter.HOOKS] = changed[adapter.HOOKS]
    try:
        adapter.transform(partial)
    except ValueError:
        pass
    else:
        raise AssertionError("Partial adaptation must be rejected")
    reference = fixture_sources(LEGACY_REV, (adapter.HOOKS, adapter.FS))
    for path, function in ((adapter.HOOKS, "selinux_setprocattr"),
                           (adapter.FS, "sel_write_context"),
                           (adapter.FS, "sel_write_access")):
        assert body(changed[path], function) == body(reference[path], function), function
    print("MODIFIED: hidden-policy checks preserved; real SID and privilege checks retained; status path unchanged")
    print("PASS: three SELinux function bodies exactly match the pinned legacy reference")
    print("PASS: bool/read ABI, preinit opt-out, idempotence, immutable input, drift and partial-edit rejection")


if __name__ == "__main__":
    check(fixture_sources())
