#!/usr/bin/env bash
# sshaudit tests. Read-only; builds throwaway fixtures in a temp dir.
set -uo pipefail
cd "$(dirname "$0")/.."
SA="python3 sshaudit.py"
pass=0; fail=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

assert() {   # <desc> <expect substring> -- <cmd...>
    local desc="$1" expect="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$expect" <<<"$out"; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$desc" "$expect" "$out"; fail=$((fail+1)); fi
}
assert_exit() {  # <desc> <expected code> -- <cmd...>
    local desc="$1" want="$2"; shift 2; [[ "$1" == "--" ]] && shift
    "$@" >/dev/null 2>&1; local rc=$?
    if [[ "$rc" == "$want" ]]; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s (exit %s, wanted %s)\n' "$desc" "$rc" "$want"; fail=$((fail+1)); fi
}

echo "== syntax =="
if python3 -c "import ast; ast.parse(open('sshaudit.py').read())"; then
    echo "  PASS  sshaudit.py parses"; pass=$((pass+1))
else echo "  FAIL  syntax"; fail=$((fail+1)); fi

echo "== sshd_config findings =="
cat > "$T/weak" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
Ciphers aes256-cbc,3des-cbc,aes256-gcm@openssh.com
MACs hmac-md5,hmac-sha2-256
KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256
EOF
assert "flags root login"       "HIGH     PermitRootLogin"        -- $SA sshd --config "$T/weak" --no-color
assert "flags empty passwords"  "CRITICAL PermitEmptyPasswords"   -- $SA sshd --config "$T/weak" --no-color
assert "flags CBC cipher"       "aes256-cbc"                      -- $SA sshd --config "$T/weak" --no-color
assert "flags md5 MAC"          "hmac-md5"                        -- $SA sshd --config "$T/weak" --no-color
assert "flags weak kex"         "diffie-hellman-group1-sha1"      -- $SA sshd --config "$T/weak" --no-color
assert_exit "weak config exits non-zero" 1 -- $SA sshd --config "$T/weak" --no-color

cat > "$T/good" <<'EOF'
PermitRootLogin no
PasswordAuthentication no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256
EOF
assert "clean config passes"    "no risky directives found"       -- $SA sshd --config "$T/good" --no-color
assert_exit "clean config exits zero" 0 -- $SA sshd --config "$T/good" --no-color

echo "== public key findings =="
if command -v ssh-keygen >/dev/null 2>&1; then
    ssh-keygen -q -t rsa -b 2048 -N "" -C "small@t"  -f "$T/r2" 2>/dev/null
    ssh-keygen -q -t rsa -b 4096 -N "" -C "strong@t" -f "$T/r4" 2>/dev/null
    ssh-keygen -q -t ed25519    -N "" -C "ed@t"      -f "$T/ed" 2>/dev/null
    cat "$T"/r2.pub "$T"/r4.pub "$T"/ed.pub > "$T/ak"
    assert "computes RSA 2048 from blob" "RSA 2048-bit" -- $SA keys --file "$T/ak" --no-color
    assert "computes RSA 4096 from blob" "RSA 4096-bit" -- $SA keys --file "$T/ak" --no-color
    assert "ed25519 marked ok"           "ed25519"      -- $SA keys --file "$T/ak" --no-color
    assert "2048 flagged medium"         "MEDIUM"        -- $SA keys --file "$T/ak" --no-color
else
    echo "  SKIP  ssh-keygen not installed"
fi
# a DSA key line (static fixture; ssh-keygen may refuse to make DSA now)
echo "ssh-dss AAAAB3NzaC1kc3MAAACBmock legacy@t" > "$T/dsa"
assert "DSA key is critical" "CRITICAL" -- $SA keys --file "$T/dsa" --no-color

echo
echo "== $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
