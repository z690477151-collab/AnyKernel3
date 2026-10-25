#!/usr/bin/env python3
"""Restore the known 7f1c299a/c06d5f8e SELinux wiring on SUSFS 5419f4ee.
This is a compatibility baseline, not a claim to retain later SELinux fixes.
Only existing source files are edited; all validation precedes writes.
"""
import argparse
import re
import subprocess
from pathlib import Path

KSU_REV = "7f1c299af463d008e66e714077eb6a8079ff722b"
SUSFS_REV = "5419f4ee97cc8bf7ca67a9ff207f39653d7784f4"
MARKER = "/* legacy_susfs: 7f1c299a + 5419f4ee; SELinux behavior from c06d5f8e. */\n"
HOOKS = "security/selinux/hooks.c"
FS = "security/selinux/selinuxfs.c"
EXEC = "fs/exec.c"
READ = "fs/read_write.c"
SUCOMPAT_PATHS = (EXEC, "fs/open.c", "fs/stat.c")
PATHS = (HOOKS, FS, *SUCOMPAT_PATHS, READ)

# Exact hiding hunks from susfs4ksu c06d5f8e, excluding status-page changes.
# In setprocattr the fake SID is only a precheck; the real policy supplies sid.
CHANGES = (
    ("security/selinux/hooks.c", "\tu32 mysid = current_sid(), sid = 0, ptsid;\n\tint error;\n\tchar *str = value;\n\n\t/*\n\t * Basic control over ability to set these attributes at all.\n", "\tu32 mysid = current_sid(), sid = 0, ptsid;\n\tint error;\n\tchar *str = value;\n#ifdef CONFIG_KSU_SUSFS\n\tbool should_check_current = (likely(!strcmp(name, \"current\") &&\n\t\t\t\t\t\t\t\t current_uid().val >= 10000 &&\n\t\t\t\t\t\t\t\t ksu_selinux_hide_running));\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\t/*\n\t * Basic control over ability to set these attributes at all.\n"),
    ("security/selinux/hooks.c", "\t\t\tstr[size-1] = 0;\n\t\t\tsize--;\n\t\t}\n\t\terror = security_context_to_sid(&selinux_state, value, size,\n\t\t\t\t\t\t&sid, GFP_KERNEL);\n\t\tif (error == -EINVAL && !strcmp(name, \"fscreate\")) {\n", "\t\t\tstr[size-1] = 0;\n\t\t\tsize--;\n\t\t}\n#ifdef CONFIG_KSU_SUSFS\n\t\tif (should_check_current) {\n\t\t\tu32 tmp_sid = 0;\n\t\t\tint fake_error = security_context_to_sid(&fake_state, value, size, &tmp_sid, GFP_KERNEL);\n\t\t\tif (fake_error)\n\t\t\t\treturn fake_error;\n\t\t}\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\t\terror = security_context_to_sid(&selinux_state, value, size,\n\t\t\t\t\t\t&sid, GFP_KERNEL);\n\t\tif (error == -EINVAL && !strcmp(name, \"fscreate\")) {\n"),
    ("security/selinux/selinuxfs.c", "\tchar *canon = NULL;\n\tu32 sid, len;\n\tssize_t length;\n\n\tlength = avc_has_perm(&selinux_state,\n\t\t\t      current_sid(), SECINITSID_SECURITY,\n", "\tchar *canon = NULL;\n\tu32 sid, len;\n\tssize_t length;\n#ifdef CONFIG_KSU_SUSFS\n\tbool should_check_current = (likely(current_uid().val >= 10000 && ksu_selinux_hide_running));\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\tlength = avc_has_perm(&selinux_state,\n\t\t\t      current_sid(), SECINITSID_SECURITY,\n"),
    ("security/selinux/selinuxfs.c", "\tif (length)\n\t\tgoto out;\n\n\tlength = security_context_to_sid(state, buf, size, &sid, GFP_KERNEL);\n\tif (length)\n\t\tgoto out;\n\n\tlength = security_sid_to_context(state, sid, &canon, &len);\n\tif (length)\n\t\tgoto out;\n\n\tlength = -ERANGE;\n\tif (len > SIMPLE_TRANSACTION_LIMIT) {\n\t\tpr_err(\"SELinux: %s:  context size (%u) exceeds \"\n", "\tif (length)\n\t\tgoto out;\n\n#ifdef CONFIG_KSU_SUSFS\n\tif (should_check_current) {\n\t\tlength = security_context_to_sid(&fake_state, buf, size, &sid, GFP_KERNEL);\n\t\tif (length)\n\t\t\tgoto out;\n\t\tgoto bypass_orig_flow1;\n\t}\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\tlength = security_context_to_sid(state, buf, size, &sid, GFP_KERNEL);\n\tif (length)\n\t\tgoto out;\n\n#ifdef CONFIG_KSU_SUSFS\nbypass_orig_flow1:\n\tif (should_check_current) {\n\t\tlength = security_sid_to_context(&fake_state, sid, &canon, &len);\n\t\tif (length)\n\t\t\tgoto out;\n\t\tgoto bypass_orig_flow2;\n\t}\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\tlength = security_sid_to_context(state, sid, &canon, &len);\n\tif (length)\n\t\tgoto out;\n\n#ifdef CONFIG_KSU_SUSFS\nbypass_orig_flow2:\n#endif // #ifdef CONFIG_KSU_SUSFS\n\tlength = -ERANGE;\n\tif (len > SIMPLE_TRANSACTION_LIMIT) {\n\t\tpr_err(\"SELinux: %s:  context size (%u) exceeds \"\n"),
    ("security/selinux/selinuxfs.c", "\tu16 tclass;\n\tstruct av_decision avd;\n\tssize_t length;\n\n\tlength = avc_has_perm(&selinux_state,\n\t\t\t      current_sid(), SECINITSID_SECURITY,\n", "\tu16 tclass;\n\tstruct av_decision avd;\n\tssize_t length;\n#ifdef CONFIG_KSU_SUSFS\n\tbool should_check_current = (likely(current_uid().val >= 10000 && ksu_selinux_hide_running));\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\tlength = avc_has_perm(&selinux_state,\n\t\t\t      current_sid(), SECINITSID_SECURITY,\n"),
    ("security/selinux/selinuxfs.c", "\tif (sscanf(buf, \"%s %s %hu\", scon, tcon, &tclass) != 3)\n\t\tgoto out;\n\n\tlength = security_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);\n\tif (length)\n\t\tgoto out;\n\n\tlength = security_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);\n\tif (length)\n\t\tgoto out;\n\n\tsecurity_compute_av_user(state, ssid, tsid, tclass, &avd);\n\n\tlength = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT,\n\t\t\t  \"%x %x %x %x %u %x\",\n\t\t\t  avd.allowed, 0xffffffff,\n", "\tif (sscanf(buf, \"%s %s %hu\", scon, tcon, &tclass) != 3)\n\t\tgoto out;\n\n#ifdef CONFIG_KSU_SUSFS\n\tif (should_check_current) {\n\t\tlength = security_context_str_to_sid(&fake_state, scon, &ssid, GFP_KERNEL);\n\t\tif (length)\n\t\t\tgoto out;\n\t\tgoto bypass_orig_flow1;\n\t}\n#endif // #ifdef CONFIG_KSU_SUSFS\n\tlength = security_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);\n\tif (length)\n\t\tgoto out;\n\n#ifdef CONFIG_KSU_SUSFS\nbypass_orig_flow1:\n\tif (should_check_current) {\n\t\tlength = security_context_str_to_sid(&fake_state, tcon, &tsid, GFP_KERNEL);\n\t\tif (length)\n\t\t\tgoto out;\n\t\tgoto bypass_orig_flow2;\n\t}\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\tlength = security_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);\n\tif (length)\n\t\tgoto out;\n\n#ifdef CONFIG_KSU_SUSFS\nbypass_orig_flow2:\n\tif (should_check_current) {\n\t\tsecurity_compute_av_user(&fake_state, ssid, tsid, tclass, &avd);\n\t\tgoto bypass_orig_flow3;\n\t}\n#endif // #ifdef CONFIG_KSU_SUSFS\n\n\tsecurity_compute_av_user(state, ssid, tsid, tclass, &avd);\n\n#ifdef CONFIG_KSU_SUSFS\nbypass_orig_flow3:\n#endif // #ifdef CONFIG_KSU_SUSFS\n\tlength = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT,\n\t\t\t  \"%x %x %x %x %u %x\",\n\t\t\t  avd.allowed, 0xffffffff,\n"),
)
WRAPPERS = {
    "handle_selinux_setprocattr": "#ifdef CONFIG_KSU_SUSFS\nstatic int handle_selinux_setprocattr(const char *name, void *value, size_t size)\n{\n\tif ((likely(!strcmp(name, \"current\") &&\n\t\t\t\tcurrent_uid().val >= 10000 &&\n\t\t\t\tksu_selinux_hide_running)))\n\t\treturn my_setprocattr(name, value, size);\n\treturn selinux_setprocattr(name, value, size);\n}\n#endif // #ifdef CONFIG_KSU_SUSFS\n",
    "handle_sel_write_context": "#ifdef CONFIG_KSU_SUSFS\nstatic ssize_t handle_sel_write_context(struct file *file, char *buf, size_t size) {\n\tif ((likely(current_uid().val >= 10000 && ksu_selinux_hide_running)))\n\t\treturn my_write_context(file, buf, size);\n\treturn sel_write_context(file, buf, size);\n}\n#endif // #ifdef CONFIG_KSU_SUSFS\n",
    "handle_sel_write_access": "#ifdef CONFIG_KSU_SUSFS\nstatic ssize_t handle_sel_write_access(struct file *file, char *buf, size_t size)\n{\n\tif ((likely(current_uid().val >= 10000 && ksu_selinux_hide_running)))\n\t\treturn my_write_access(file, buf, size);\n\treturn sel_write_access(file, buf, size);\n}\n#endif // #ifdef CONFIG_KSU_SUSFS\n",
}


def once(text, before, after, label):
    count = text.count(before)
    if count != 1:
        raise ValueError(f"{label}: expected one known source block, found {count}")
    return text.replace(before, after, 1)


def validate(result):
    if result[READ].count("extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);") != 1 or result[READ].count("(void)ksu_handle_sys_read(fd, &buf, &count);") != 1:
        raise ValueError("fs/read_write.c: legacy read-hook signature mismatch")
    for path in SUCOMPAT_PATHS:
        if result[path].count("extern bool ksu_su_compat_enabled;") != 1 or result[path].count("READ_ONCE(ksu_su_compat_enabled)") != 1:
            raise ValueError(f"{path}: legacy sucompat bool wiring mismatch")
        if "static_branch_likely(&ksu_su_compat_enabled)" in result[path]:
            raise ValueError(f"{path}: bool must not be interpreted as a static key")
    for path, _, after in CHANGES:
        if result[path].count(after) != 1:
            raise ValueError(f"{path}: legacy hiding block missing or ambiguous")
    for path in (HOOKS, FS):
        if any(name in result[path] for name in
               ("my_setprocattr", "my_write_context", "my_write_access",
                "handle_selinux_setprocattr", "handle_sel_write_context",
                "handle_sel_write_access")):
            raise ValueError(f"{path}: unresolved new SELinux wiring")
        if result[path].count("extern struct selinux_state fake_state;") != 1:
            raise ValueError(f"{path}: fake_state declaration mismatch")
    if result[EXEC].count("#define KSU_NO_PREINIT 1") != 1:
        raise ValueError("fs/exec.c: unsupported preinit was not disabled")
    if len(re.findall(r"^#ifndef KSU_NO_PREINIT$", result[EXEC], re.M)) != 4:
        raise ValueError("fs/exec.c: unexpected preinit guard layout")
    for path in PATHS:
        if result[path].count(MARKER) != 1:
            raise ValueError(f"{path}: incomplete adaptation")


def transform(sources):
    """Pure transformation of six UTF-8 source texts; no filesystem writes."""
    result = dict(sources)
    if any(MARKER in result[p] for p in PATHS):
        validate(result)
        return result
    for path in PATHS:
        if "\r" in result[path]:
            raise ValueError(f"{path}: expected LF source")
    result[READ] = once(result[READ],
                        "extern __attribute__((cold)) void ksu_handle_sys_read(unsigned int fd);",
                        "extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);", READ)
    result[READ] = once(result[READ], "\t\tksu_handle_sys_read(fd);",
                        "\t\t(void)ksu_handle_sys_read(fd, &buf, &count);", READ)
    for path in SUCOMPAT_PATHS:
        result[path] = once(result[path],
                            "extern struct static_key_true ksu_su_compat_enabled;",
                            "extern bool ksu_su_compat_enabled;", path)
        result[path] = once(result[path],
                            "static_branch_likely(&ksu_su_compat_enabled)",
                            "READ_ONCE(ksu_su_compat_enabled)", path)
    result[HOOKS] = once(
        result[HOOKS],
        "extern int my_setprocattr(const char *name, void *value, size_t size);",
        "extern struct selinux_state fake_state;", HOOKS)
    result[FS] = once(
        result[FS],
        "extern ssize_t my_write_context(struct file *file, char *buf, size_t size);\n"
        "extern ssize_t my_write_access(struct file *file, char *buf, size_t size);",
        "extern struct selinux_state fake_state;", FS)
    for name, block in WRAPPERS.items():
        path = HOOKS if name == "handle_selinux_setprocattr" else FS
        result[path] = once(result[path], block, "", name)
    result[FS] = once(
        result[FS],
        "#ifdef CONFIG_KSU_SUSFS\n"
        "static ssize_t handle_sel_write_access(struct file *file, char *buf, size_t size);\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS\n", "", "access forward declaration")
    for path, wrapped, original in (
        (HOOKS, "\tLSM_HOOK_INIT(setprocattr, handle_selinux_setprocattr),",
         "\tLSM_HOOK_INIT(setprocattr, selinux_setprocattr),"),
        (FS, "\t[SEL_ACCESS] = handle_sel_write_access,", "\t[SEL_ACCESS] = sel_write_access,"),
        (FS, "\t[SEL_CONTEXT] = handle_sel_write_context,", "\t[SEL_CONTEXT] = sel_write_context,"),
    ):
        block = ("#ifdef CONFIG_KSU_SUSFS\n" + wrapped + "\n#else\n" +
                 original + "\n#endif // #ifdef CONFIG_KSU_SUSFS\n")
        result[path] = once(result[path], block, original + "\n", wrapped)
    for path, before, after in CHANGES:
        result[path] = once(result[path], before, after, path)
    # 7f1c299a never implemented module preinit. Use the upstream opt-out guard.
    if "#define KSU_NO_PREINIT" in result[EXEC]:
        raise ValueError("fs/exec.c: unexpected existing preinit override")
    if len(re.findall(r"^#ifndef KSU_NO_PREINIT$", result[EXEC], re.M)) != 4:
        raise ValueError("fs/exec.c: latest preinit hooks missing or changed")
    result[EXEC] = "#define KSU_NO_PREINIT 1\n" + result[EXEC]
    for path in PATHS:
        result[path] = MARKER + result[path]
    validate(result)
    return result


def revision(path):
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("common", type=Path)
    parser.add_argument("kernelsu", type=Path)
    parser.add_argument("susfs", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="validate and report the planned changes without writing")
    args = parser.parse_args()
    if revision(args.kernelsu) != KSU_REV or revision(args.susfs) != SUSFS_REV:
        raise ValueError("unsupported source revisions; refusing compatibility edits")
    makefile = (args.common / "Makefile").read_text(encoding="utf-8")
    versions = {k: int(v) for k, v in re.findall(
        r"^(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(\d+)\s*$", makefile, re.M)}
    if versions != {"VERSION": 5, "PATCHLEVEL": 10, "SUBLEVEL": 236}:
        raise ValueError(f"only the reviewed Android12 5.10.236 target is supported: {versions}")
    hide = (args.kernelsu / "kernel/feature/selinux_hide.c").read_text(encoding="utf-8")
    if "struct selinux_state fake_state;" not in hide or any(
        name in hide for name in ("my_write_context", "my_write_access", "my_setprocattr")
    ):
        raise ValueError("unexpected KernelSU SELinux implementation")
    sucompat = (args.kernelsu / "kernel/feature/sucompat.c").read_text(encoding="utf-8")
    ksud = (args.kernelsu / "kernel/runtime/ksud.c").read_text(encoding="utf-8")
    if not re.search(r"^bool ksu_su_compat_enabled\b", sucompat, re.M) or not re.search(r"\bint ksu_handle_sys_read\(unsigned int fd, char __user \*\*buf_ptr, size_t \*count_ptr\)", ksud):
        raise ValueError("unexpected KernelSU sucompat/read-hook ABI")
    sources = {p: (args.common / p).read_text(encoding="utf-8") for p in PATHS}
    result = transform(sources)
    for path in PATHS:
        if result[path] != sources[path]:
            if not args.check:
                (args.common / path).write_text(result[path], encoding="utf-8", newline="\n")
            print(("CHECK " if args.check else "APPLIED ") + path)
    print("PASS: legacy SELinux wiring retained; unsupported preinit explicitly disabled")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"ERROR: {error}")

