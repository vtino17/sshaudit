# sshaudit

Audit SSH for the two things that quietly weaken it on a lot of hosts:

- an **`sshd_config`** that still allows root or password login, or negotiates
  CBC / SHA-1 / MD5 crypto, and
- **`authorized_keys`** files full of undersized RSA keys or deprecated DSA keys
  that nobody has rotated.

sshaudit reads both, reports findings by severity, and changes nothing. It is a
single Python file with no dependencies. Its exit status is non-zero when
anything is HIGH or CRITICAL, so it drops straight into CI or a cron check.

## Usage

```sh
python3 sshaudit.py sshd  --config /etc/ssh/sshd_config
python3 sshaudit.py keys  --file ~/.ssh/authorized_keys
python3 sshaudit.py all               # sshd_config + every default key file
```

Example:

```
$ python3 sshaudit.py sshd --config /etc/ssh/sshd_config
  CRITICAL PermitEmptyPasswords: empty passwords are accepted
  HIGH     PermitRootLogin: root can log in directly; set to 'no' or 'prohibit-password'
  HIGH     Ciphers: weak algorithm negotiated: aes256-cbc
  HIGH     MACs: weak algorithm negotiated: hmac-md5
  MEDIUM   PasswordAuthentication: passwords accepted; prefer key-only ('no')

  1 critical, 3 high, 1 medium
```

## What it checks

**`sshd_config`** (respecting sshd's first-value-wins rule): `PermitRootLogin`,
`PasswordAuthentication`, `PermitEmptyPasswords`, obsolete `Protocol 1`,
`PubkeyAuthentication`, `MaxAuthTries`, `X11Forwarding`, and weak entries in
`Ciphers` (CBC, 3DES, arcfour), `MACs` (MD5, 96-bit, SHA-1) and `KexAlgorithms`
(group1-sha1, group-exchange-sha1, group14-sha1).

**Public keys** — it base64-decodes each key and reads the wire format directly:

- `ssh-dss` (DSA) → **CRITICAL** (deprecated, disabled by default in modern OpenSSH)
- `ssh-rsa` → the **modulus length is read out of the key blob**: < 2048-bit is
  CRITICAL, < 3072-bit is MEDIUM, 3072+ is OK
- `ecdsa-*` → LOW (works, but ed25519 is preferred)
- `ssh-ed25519` → OK

Reading the RSA size from the blob means it reports the real key strength, not
whatever the trailing comment claims.

## Caveat

This checks the settings and keys it can see. It is a fast hygiene gate, not a
full SSH penetration test, and it does not connect to anything. Read a finding
before acting on it — for example, some bastion/legacy setups keep
`PasswordAuthentication yes` deliberately behind other controls.

## Tests

```sh
./tests/run.sh
```

Generates throwaway keys and configs in a temp dir, asserts the findings, and
cleans up. Read-only, no root needed.

## License

MIT. See `LICENSE`.
