# Hard_Scope 🛡️

**A read-only, CIS-lite local hardening audit.** Inspect the highest-signal filesystem and SSH settings in one pass and get a pass / fail / warn verdict per check — with severity, detail, and a remediation hint. Zero dependencies, pure Python stdlib, and strictly read-only: nothing is ever modified.

## Why it exists

Most hosts are one forgotten permission bit away from a bad day: a world-writable file in `$HOME`, a `sudoers` that the wrong group can edit, root SSH left on. Hard_Scope turns that audit into a single command — no config to write, no agent to install. Run `audit` for a human read-out, `score --fail-critical` as a CI gate that exits non-zero when a critical check fails, and `baseline` to capture the current posture as machine-readable JSON.

## One tool, many domains

| Domain | What Hard_Scope does for you |
|---|---|
| **Security** | Flags world-writable files, loose password-database perms, and risky SSH settings before they become incidents |
| **DevOps / CI** | `score --fail-critical` returns a non-zero exit that drops straight into a pipeline gate |
| **Agentic AI** | Gives LLM agents a read-only, JSON-native way to establish host posture and cite the failing check |
| **Compliance** | Produces a `baseline` snapshot you can diff over time to prove drift control |
| **Onboarding** | A single command that tells a new engineer exactly how a box is configured |

## Install

```bash
git clone git@github.com:realMNohgee/Hard_Scope.git
cd Hard_Scope
python3 Hard_Scope.py --help
```

## Quick start

```bash
python3 Hard_Scope.py audit
```

```
Hard_Scope — read-only hardening audit

[PASS] Password database permissions (critical)
        /etc/master.passwd mode 0o600
[PASS] sudoers permissions (critical)
        /etc/sudoers mode 0o440 (expected 0440)
[FAIL] World-writable files in /tmp (critical)
        0 world-writable file(s) under /tmp
[FAIL] World-writable files in $HOME (critical)
        1 world-writable file(s) under /Users/you: /Users/you/.cache/uv/.lock
        fix: chmod o-w each listed file; audit why it was created world-writable
```

### CI gate

```bash
python3 Hard_Scope.py score --fail-critical
echo "exit=$?"
# exit=1  (a critical check failed)
```

### Machine-readable baseline

```bash
python3 Hard_Scope.py baseline --format json
```

```json
{
  "tool": "Hard_Scope",
  "type": "baseline",
  "timestamp": "2026-10-07T00:00:00+00:00",
  "summary": { "total": 9, "pass": 5, "fail": 1, "warn": 2, "skip": 1, "critical_failures": 1 },
  "checks": [ { "id": "password_db", "title": "Password database permissions", "severity": "critical", "status": "pass", "detail": "/etc/master.passwd mode 0o600", "remediation": "..." } ]
}
```

## Checks

| Check | Severity | What it inspects |
|---|---|---|
| `password_db` | critical | `/etc/shadow` or `/etc/master.passwd` has no group/other bits |
| `sudoers` | critical | `/etc/sudoers` is not group/other writable or world readable |
| `tmp_world_writable` | critical | world-writable regular files under `/tmp` |
| `home_world_writable` | critical | world-writable regular files under `$HOME` |
| `suid_usr_bin` | info | SUID/SGID binaries in `/usr/bin` (expected set) |
| `suid_usr_local` | critical | SUID/SGID binaries in `/usr/local/bin` (should be empty) |
| `ssh_permit_root_login` | critical | `PermitRootLogin` in `/etc/ssh/sshd_config` |
| `ssh_password_auth` | warning | `PasswordAuthentication` in `/etc/ssh/sshd_config` |
| `umask` | warning | process umask is 0022 or stricter |

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
