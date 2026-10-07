#!/usr/bin/env python3
"""Hard_Scope — a read-only, CIS-lite local hardening audit.

Hard_Scope inspects a small set of high-signal filesystem and SSH settings and
reports a pass / fail / warn verdict for each one, together with a severity, a
short detail line, and a remediation hint. It never modifies the system: every
check only reads state. Use `baseline` to capture the current posture as JSON,
and `score --fail-critical` as a CI gate.

Zero dependencies — Python standard library only.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import stat
import sys

# --- severity + status vocabulary -------------------------------------------

CRITICAL = "critical"   # a failing CRITICAL check fails `score --fail-critical`
WARNING = "warning"     # worth fixing, but not a gate
INFO = "info"           # purely informational

PASS = "pass"
FAIL = "fail"
WARN = "warn"
SKIP = "skip"

# Where the SSH daemon configuration normally lives.
SSHD_CONFIG = "/etc/ssh/sshd_config"

# World-writable scan bounds: how deep to walk and how many entries to inspect.
_WW_MAXDEPTH = 3
_WW_CAP = 200000


def _result(check_id, title, severity, status, detail, remediation):
    """Build one uniformly-shaped check-result dict."""
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "status": status,
        "detail": detail,
        "remediation": remediation,
    }


def _mode(path):
    """Return the permission bits (e.g. 0o644) of `path`."""
    return stat.S_IMODE(os.stat(path).st_mode)


def _scan_world_writable(root, maxdepth=_WW_MAXDEPTH, cap=_WW_CAP):
    """Walk `root` (bounded depth) and return (findings, capped_flag).

    Only regular files that are world-writable are reported; symlinks are
    skipped and the walk never follows links, so this stays strictly read-only.
    """
    findings = []
    if not os.path.isdir(root):
        return findings, False
    base = os.path.abspath(root).rstrip(os.sep)
    base_depth = base.count(os.sep)  # depth of the root itself
    seen = 0
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= maxdepth:
            dirnames[:] = []  # stop descending, but still inspect this level
        # Never descend through symlinked directories (avoids loops / escapes).
        dirnames[:] = [
            d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))
        ]
        for name in filenames:
            seen += 1
            if seen > cap:
                return findings, True
            fp = os.path.join(dirpath, name)
            try:
                st = os.lstat(fp)
            except OSError:
                continue  # unreadable / vanished mid-walk: skip quietly
            if stat.S_ISLNK(st.st_mode):
                continue
            if stat.S_ISREG(st.st_mode) and (st.st_mode & stat.S_IWOTH):
                findings.append(fp)
    return findings, False


def _suid_binaries(directory):
    """Return sorted paths of SUID/SGID regular files directly under `directory`."""
    out = []
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        fp = os.path.join(directory, name)
        try:
            st = os.lstat(fp)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
            out.append(fp)
    return out


def _read_sshd_directives(path):
    """Parse sshd_config into a {lowercased_key: value} dict (comments skipped).

    Returns (directives, error) where error is a message when the file is
    missing or unreadable.
    """
    if not os.path.exists(path):
        return None, "configuration file not present"
    directives = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue  # blank line or comment
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                key = parts[0].lower()
                value = parts[1].split("#", 1)[0].strip().lower()
                directives[key] = value
    except OSError as exc:
        return None, f"unreadable: {exc}"
    return directives, None


def _current_umask():
    """Read the process umask without leaving it changed (set then restore)."""
    cur = os.umask(0)   # momentarily expose the value
    os.umask(cur)       # restore immediately
    return cur


# --- individual checks -------------------------------------------------------

def check_password_db():
    """Verify the shadow / master password file is not group/other accessible."""
    candidates = ["/etc/shadow", "/etc/master.passwd"]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path is None:
        return _result("password_db", "Password database permissions", INFO, SKIP,
                       "no /etc/shadow or /etc/master.passwd present",
                       "n/a")
    try:
        mode = _mode(path)
    except OSError as exc:
        return _result("password_db", "Password database permissions", CRITICAL, FAIL,
                       f"{path} unreadable: {exc}",
                       "ensure the password database exists and is root-only")
    ok = (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0  # no group/other bits at all
    detail = f"{path} mode {oct(mode)}"
    return _result(
        "password_db", "Password database permissions", CRITICAL,
        PASS if ok else FAIL, detail,
        "chmod 0600 and chown root:root the password database",
    )


def check_sudoers():
    """Verify /etc/sudoers is not group/other writable or world readable."""
    path = "/etc/sudoers"
    if not os.path.exists(path):
        return _result("sudoers", "sudoers permissions", WARNING, SKIP,
                       "/etc/sudoers not present", "n/a")
    try:
        mode = _mode(path)
    except OSError as exc:
        return _result("sudoers", "sudoers permissions", CRITICAL, FAIL,
                       f"{path} unreadable: {exc}", "restore /etc/sudoers to 0440 root:root")
    # Group/other must have no write, and others must have no read.
    ok = (mode & (stat.S_IWGRP | stat.S_IRWXO)) == 0
    detail = f"{path} mode {oct(mode)} (expected 0440)"
    return _result(
        "sudoers", "sudoers permissions", CRITICAL, PASS if ok else FAIL, detail,
        "chmod 0440 and chown root:wheel /etc/sudoers",
    )


def check_tmp_world_writable():
    """Flag world-writable regular files under /tmp (sticky dirs are ignored)."""
    findings, capped = _scan_world_writable("/tmp", maxdepth=4)
    detail = f"{len(findings)} world-writable file(s) under /tmp"
    if capped:
        detail += " (scan capped)"
    if findings:
        detail += ": " + ", ".join(findings[:3])
    return _result(
        "tmp_world_writable", "World-writable files in /tmp", CRITICAL,
        FAIL if findings else PASS, detail,
        "chmod o-w each listed file; files in /tmp must not be writable by all",
    )


def check_home_world_writable():
    """Flag world-writable regular files under $HOME (bounded-depth walk)."""
    home = os.path.expanduser("~")
    findings, capped = _scan_world_writable(home)
    detail = f"{len(findings)} world-writable file(s) under {home}"
    if capped:
        detail += " (scan capped)"
    if findings:
        detail += ": " + ", ".join(findings[:3])
    return _result(
        "home_world_writable", "World-writable files in $HOME", CRITICAL,
        FAIL if findings else PASS, detail,
        "chmod o-w each listed file; audit why it was created world-writable",
    )


def check_suid_usr_bin():
    """Report SUID/SGID binaries in /usr/bin (expected set — informational)."""
    found = _suid_binaries("/usr/bin")
    detail = f"{len(found)} SUID/SGID binar(ies) in /usr/bin"
    if found:
        detail += ": " + ", ".join(os.path.basename(p) for p in found[:6])
        if len(found) > 6:
            detail += ", ..."
    return _result(
        "suid_usr_bin", "SUID/SGID binaries in /usr/bin", INFO, PASS, detail,
        "n/a — review any binary you did not expect to see",
    )


def check_suid_usr_local():
    """Flag SUID/SGID binaries in /usr/local/bin (should normally be empty)."""
    found = _suid_binaries("/usr/local/bin")
    detail = f"{len(found)} SUID/SGID binar(ies) in /usr/local/bin"
    if found:
        detail += ": " + ", ".join(found[:6])
    return _result(
        "suid_usr_local", "SUID/SGID binaries in /usr/local/bin", CRITICAL,
        FAIL if found else PASS, detail,
        "chmod u-s,g-s each listed binary unless elevation is truly required",
    )


def check_ssh_permit_root_login():
    """Fail when sshd explicitly permits root login."""
    directives, error = _read_sshd_directives(SSHD_CONFIG)
    if directives is None:
        return _result("ssh_permit_root_login", "SSH PermitRootLogin", CRITICAL, SKIP,
                       error, "n/a")
    value = directives.get("permitrootlogin")
    if value is None:
        return _result("ssh_permit_root_login", "SSH PermitRootLogin", CRITICAL, WARN,
                       "not set explicitly (distro default applies)",
                       "set 'PermitRootLogin no' in /etc/ssh/sshd_config")
    ok = value != "yes"
    return _result(
        "ssh_permit_root_login", "SSH PermitRootLogin", CRITICAL,
        PASS if ok else FAIL, f"PermitRootLogin {value}",
        "set 'PermitRootLogin no' in /etc/ssh/sshd_config",
    )


def check_ssh_password_auth():
    """Warn when sshd explicitly enables password authentication."""
    directives, error = _read_sshd_directives(SSHD_CONFIG)
    if directives is None:
        return _result("ssh_password_auth", "SSH PasswordAuthentication", WARNING, SKIP,
                       error, "n/a")
    value = directives.get("passwordauthentication")
    if value is None:
        return _result("ssh_password_auth", "SSH PasswordAuthentication", WARNING, WARN,
                       "not set explicitly (distro default applies)",
                       "prefer 'PasswordAuthentication no' and key-based auth")
    ok = value != "yes"
    return _result(
        "ssh_password_auth", "SSH PasswordAuthentication", WARNING,
        PASS if ok else WARN, f"PasswordAuthentication {value}",
        "prefer 'PasswordAuthentication no' and key-based auth",
    )


def check_umask():
    """Warn if the process umask is looser than 0022 (group/other writable)."""
    mask = _current_umask()
    # A mask that keeps 0022 set denies group/other write — the minimum bar.
    ok = (mask & 0o022) == 0o022
    return _result(
        "umask", "Process umask", WARNING, PASS if ok else WARN,
        f"umask {oct(mask)} (target 0022 or stricter)",
        "set 'umask 022' (or 077) in the shell profile",
    )


def run_checks():
    """Execute every check in a stable order and return the result list."""
    return [
        check_password_db(),
        check_sudoers(),
        check_tmp_world_writable(),
        check_home_world_writable(),
        check_suid_usr_bin(),
        check_suid_usr_local(),
        check_ssh_permit_root_login(),
        check_ssh_password_auth(),
        check_umask(),
    ]


def _summarize(results):
    """Aggregate pass/fail/warn/skip counts plus the critical-failure count."""
    counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0}
    critical_failures = 0
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        if r["status"] == FAIL and r["severity"] == CRITICAL:
            critical_failures += 1
    return {
        "total": len(results),
        "pass": counts[PASS],
        "fail": counts[FAIL],
        "warn": counts[WARN],
        "skip": counts[SKIP],
        "critical_failures": critical_failures,
    }


def _print_checks(results):
    """Render every check result as aligned, human-readable lines."""
    print("Hard_Scope — read-only hardening audit")
    print()
    for r in results:
        tag = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", SKIP: "SKIP"}[r["status"]]
        print(f"[{tag}] {r['title']} ({r['severity']})")
        print(f"        {r['detail']}")
        if r["status"] in (FAIL, WARN):
            print(f"        fix: {r['remediation']}")


def _print_score(results, summary):
    """Render the score summary plus a remediation line for each failure."""
    print("Hard_Scope — score")
    print(f"checks:            {summary['total']}")
    print(f"pass:              {summary['pass']}")
    print(f"fail:              {summary['fail']}")
    print(f"warn:              {summary['warn']}")
    print(f"skip:              {summary['skip']}")
    print(f"critical failures: {summary['critical_failures']}")
    failing = [r for r in results if r["status"] == FAIL]
    if failing:
        print()
        for r in failing:
            print(f"FAIL  {r['title']}")
            print(f"      {r['detail']}")
            print(f"      fix: {r['remediation']}")


# --- subcommands -------------------------------------------------------------

def cmd_audit(args):
    """Run all checks and report pass/fail per check (the `audit` subcommand)."""
    results = run_checks()
    if args.format == "json":
        print(json.dumps({"checks": results, "summary": _summarize(results)}, indent=2))
    else:
        _print_checks(results)
    return 0


def cmd_score(args):
    """Summarise results and optionally gate on critical failures (`score`)."""
    results = run_checks()
    summary = _summarize(results)
    if args.format == "json":
        print(json.dumps({
            "summary": summary,
            "failures": [r for r in results if r["status"] == FAIL],
            "checks": results,
        }, indent=2))
    else:
        _print_score(results, summary)
    # Gate: a non-zero exit only when asked and a critical check failed.
    if args.fail_critical and summary["critical_failures"] > 0:
        return 1
    return 0


def cmd_baseline(args):
    """Dump the current checks and results as a baseline snapshot (`baseline`)."""
    results = run_checks()
    snapshot = {
        "tool": "Hard_Scope",
        "type": "baseline",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": os.uname().nodename if hasattr(os, "uname") else "",
        "summary": _summarize(results),
        "checks": results,
    }
    if args.format == "json":
        print(json.dumps(snapshot, indent=2))
    else:
        _print_checks(results)
        print("\n(baseline captured — add --format json for the machine-readable dump)")
    return 0


def main(argv=None):
    """Parse arguments once and dispatch to the selected subcommand."""
    # Shared --format flag, attached to EVERY subparser via parents=[common].
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )

    parser = argparse.ArgumentParser(
        prog="Hard_Scope",
        description="Read-only, CIS-lite local hardening audit.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_audit = sub.add_parser("audit", parents=[common],
                             help="Run all checks and report pass/fail per check")
    p_audit.set_defaults(func=cmd_audit)

    p_score = sub.add_parser("score", parents=[common],
                             help="Summarise results with remediation hints")
    p_score.add_argument("--fail-critical", action="store_true",
                         help="Exit non-zero if any critical check fails")
    p_score.set_defaults(func=cmd_score)

    p_base = sub.add_parser("baseline", parents=[common],
                            help="Dump current checks and results as JSON")
    p_base.set_defaults(func=cmd_baseline)

    args = parser.parse_args(argv)  # parsed exactly once
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
