#!/usr/bin/env python3
"""sshaudit - audit SSH server config and public keys for weak, risky settings.

Two things quietly weaken SSH on a lot of hosts: an ``sshd_config`` that still
allows password or root login or negotiates CBC/SHA-1 crypto, and
``authorized_keys`` files full of small RSA keys or deprecated DSA keys that
nobody has rotated. sshaudit reads both and reports findings by severity. It
changes nothing.

    sshaudit sshd  --config /etc/ssh/sshd_config
    sshaudit keys  --file ~/.ssh/authorized_keys
    sshaudit all                       # both, at their default locations

Exit status is non-zero if any finding is HIGH or CRITICAL, so it works as a
gate in CI or a cron check.
"""
from __future__ import annotations

import argparse
import base64
import glob
import os
import struct
import sys

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "OK": 0}
COLOR = {
    "CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
    "LOW": "\033[36m", "INFO": "\033[90m", "OK": "\033[32m",
}
RESET = "\033[0m"


class Finding:
    def __init__(self, sev: str, where: str, msg: str):
        self.sev, self.where, self.msg = sev, where, msg


# ---------------------------------------------------------------------------
# sshd_config
# ---------------------------------------------------------------------------

# substrings that indicate a weak algorithm, with the severity to report
WEAK_CIPHERS = {
    "arcfour": "HIGH", "-cbc": "HIGH", "3des": "HIGH", "blowfish": "HIGH",
    "cast128": "MEDIUM", "des-": "CRITICAL",
}
WEAK_MACS = {
    "hmac-md5": "HIGH", "-96": "HIGH", "hmac-sha1": "MEDIUM", "umac-64": "MEDIUM",
}
WEAK_KEX = {
    "group1-sha1": "HIGH", "group-exchange-sha1": "HIGH",
    "group14-sha1": "MEDIUM", "gss-": "MEDIUM", "rsa1024": "HIGH",
}


def _parse_sshd(path: str) -> dict[str, str]:
    """sshd_config: keyword is case-insensitive and the FIRST value wins."""
    cfg: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key = parts[0].lower()
            if key not in cfg:            # first occurrence wins, as sshd does
                cfg[key] = parts[1].strip()
    return cfg


def _check_weak_list(value: str, table: dict[str, str], label: str,
                     out: list[Finding]) -> None:
    for algo in [a.strip().lower() for a in value.split(",")]:
        for needle, sev in table.items():
            if needle in algo:
                out.append(Finding(sev, label, f"weak algorithm negotiated: {algo}"))
                break


def audit_sshd(path: str) -> list[Finding]:
    out: list[Finding] = []
    if not os.path.exists(path):
        return [Finding("INFO", path, "no sshd_config at this path")]
    cfg = _parse_sshd(path)

    def val(key: str, default: str = "") -> str:
        return cfg.get(key, default).lower()

    # root login
    prl = val("permitrootlogin", "prohibit-password")
    if prl == "yes":
        out.append(Finding("HIGH", "PermitRootLogin", "root can log in directly; set to 'no' or 'prohibit-password'"))
    elif prl in ("no", "prohibit-password", "forced-commands-only"):
        out.append(Finding("OK", "PermitRootLogin", prl))

    # password auth
    if val("passwordauthentication", "yes") == "yes":
        out.append(Finding("MEDIUM", "PasswordAuthentication", "passwords accepted; prefer key-only ('no')"))
    else:
        out.append(Finding("OK", "PasswordAuthentication", "no"))

    if val("permitemptypasswords", "no") == "yes":
        out.append(Finding("CRITICAL", "PermitEmptyPasswords", "empty passwords are accepted"))

    # obsolete protocol
    if val("protocol") == "1" or "1" in val("protocol").split(","):
        out.append(Finding("CRITICAL", "Protocol", "SSH protocol 1 is broken; remove this line"))

    # pubkey off
    if val("pubkeyauthentication", "yes") == "no":
        out.append(Finding("MEDIUM", "PubkeyAuthentication", "public-key auth is disabled"))

    # brute-force surface
    try:
        if int(val("maxauthtries", "6")) > 6:
            out.append(Finding("LOW", "MaxAuthTries", f"{cfg.get('maxauthtries')} tries allowed per connection"))
    except ValueError:
        pass

    if val("x11forwarding", "no") == "yes":
        out.append(Finding("LOW", "X11Forwarding", "X11 forwarding enlarges the attack surface"))

    # weak crypto
    if "ciphers" in cfg:
        _check_weak_list(cfg["ciphers"], WEAK_CIPHERS, "Ciphers", out)
    if "macs" in cfg:
        _check_weak_list(cfg["macs"], WEAK_MACS, "MACs", out)
    if "kexalgorithms" in cfg:
        _check_weak_list(cfg["kexalgorithms"], WEAK_KEX, "KexAlgorithms", out)

    if not any(f.sev != "OK" and f.sev != "INFO" for f in out):
        out.append(Finding("OK", path, "no risky directives found"))
    return out


# ---------------------------------------------------------------------------
# authorized_keys / public keys
# ---------------------------------------------------------------------------

def _rsa_bits(blob: bytes) -> int | None:
    """Read the RSA modulus length out of an SSH public-key blob."""
    try:
        off = 0

        def field() -> bytes:
            nonlocal off
            (n,) = struct.unpack(">I", blob[off:off + 4])
            off += 4
            b = blob[off:off + n]
            off += n
            return b

        keytype = field()
        if keytype != b"ssh-rsa":
            return None
        field()               # public exponent e
        n = field()           # modulus
        n = n.lstrip(b"\x00")  # drop the sign byte
        return len(n) * 8
    except Exception:
        return None


# risky per-key options (in the options field before the key type)
RISKY_KEY_OPTS = {
    "no-restrictions": "note",
}


def audit_keys_file(path: str) -> list[Finding]:
    out: list[Finding] = []
    if not os.path.exists(path):
        return [Finding("INFO", path, "no key file at this path")]
    with open(path, encoding="utf-8", errors="replace") as fh:
        lineno = 0
        found = 0
        for raw in fh:
            lineno += 1
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # find the token that looks like a key type
            toks = line.split()
            ti = next((i for i, t in enumerate(toks)
                       if t.startswith(("ssh-", "ecdsa-", "sk-"))), None)
            if ti is None:
                continue
            found += 1
            where = f"{os.path.basename(path)}:{lineno}"
            keytype = toks[ti]
            b64 = toks[ti + 1] if ti + 1 < len(toks) else ""
            comment = " ".join(toks[ti + 2:]) or "(no comment)"

            if keytype in ("ssh-dss",):
                out.append(Finding("CRITICAL", where, f"DSA key (deprecated, disabled in OpenSSH) - {comment}"))
            elif keytype == "ssh-rsa":
                try:
                    blob = base64.b64decode(b64)
                except Exception:
                    out.append(Finding("LOW", where, "unparseable key blob"))
                    continue
                bits = _rsa_bits(blob)
                if bits is None:
                    out.append(Finding("LOW", where, "RSA key, size undetermined"))
                elif bits < 2048:
                    out.append(Finding("CRITICAL", where, f"RSA {bits}-bit key is far too small - {comment}"))
                elif bits < 3072:
                    out.append(Finding("MEDIUM", where, f"RSA {bits}-bit key; 3072+ recommended - {comment}"))
                else:
                    out.append(Finding("OK", where, f"RSA {bits}-bit - {comment}"))
            elif keytype.startswith("ecdsa-"):
                out.append(Finding("LOW", where, f"ECDSA key ({keytype}); ed25519 preferred - {comment}"))
            elif keytype in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
                out.append(Finding("OK", where, f"ed25519 - {comment}"))
            else:
                out.append(Finding("INFO", where, f"{keytype} - {comment}"))

            # risky option: a bare forced-command-less key with from= missing is
            # normal, so we only flag explicit danger: an empty options field is fine.
            if ti > 0:
                opts = ",".join(toks[:ti]).lower()
                if "permitopen=\"*\"" in opts.replace(" ", ""):
                    out.append(Finding("MEDIUM", where, "permitopen=\"*\" allows forwarding anywhere"))

        if found == 0:
            out.append(Finding("INFO", path, "no public keys found"))
    return out


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def report(findings: list[Finding], use_color: bool) -> int:
    worst = 0
    counts: dict[str, int] = {}
    for f in sorted(findings, key=lambda x: -SEV_ORDER[x.sev]):
        counts[f.sev] = counts.get(f.sev, 0) + 1
        worst = max(worst, SEV_ORDER[f.sev])
        tag = f"{COLOR[f.sev]}{f.sev:<8}{RESET}" if use_color else f"{f.sev:<8}"
        print(f"  {tag} {f.where}: {f.msg}")
    summary = ", ".join(f"{n} {sev.lower()}" for sev, n in
                        sorted(counts.items(), key=lambda kv: -SEV_ORDER[kv[0]]))
    print(f"\n  {summary}")
    # non-zero exit if anything is HIGH (3) or CRITICAL (4)
    return 1 if worst >= 3 else 0


def _default_key_files() -> list[str]:
    files = [os.path.expanduser("~/.ssh/authorized_keys")]
    files += glob.glob("/home/*/.ssh/authorized_keys")
    files += glob.glob("/root/.ssh/authorized_keys")
    return [f for f in dict.fromkeys(files) if os.path.exists(f)] or files[:1]


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true")
    p = argparse.ArgumentParser(prog="sshaudit", parents=[common],
                                description="audit SSH config and keys")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sshd", parents=[common], help="audit an sshd_config")
    s.add_argument("--config", default="/etc/ssh/sshd_config")
    k = sub.add_parser("keys", parents=[common], help="audit an authorized_keys / public key file")
    k.add_argument("--file", action="append", default=[])
    sub.add_parser("all", parents=[common], help="audit sshd_config and default key files")

    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color
    findings: list[Finding] = []
    if a.command == "sshd":
        findings = audit_sshd(a.config)
    elif a.command == "keys":
        files = a.file or _default_key_files()
        for f in files:
            findings += audit_keys_file(f)
    elif a.command == "all":
        findings = audit_sshd("/etc/ssh/sshd_config")
        for f in _default_key_files():
            findings += audit_keys_file(f)
    return report(findings, use_color)


if __name__ == "__main__":
    raise SystemExit(main())
