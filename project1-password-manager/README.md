# Project 1 — Secure Password Manager

The implementation is in `password-manager.js`, and it is the only file you submit.

## Run
```
npm install
npm test
```
`test/test-password-manager.js` is the provided suite. `test/test-attacks.js` contains extra
tests for swap attacks, rollback attacks, length hiding and unicode passwords.

## Design
- **Key derivation:** one PBKDF2 call (100,000 iterations, SHA-256, random 128-bit salt) produces
  a master HMAC key `k`. The sub-keys are `HMAC(k, "domain-hmac-key")`, used to MAC domain names,
  and `HMAC(k, "password-aes-gcm-key")`, used as the AES-GCM key.
- **KVS:** `kvs[Base64(HMAC(k_mac, domain))] = { iv, ct }`, so domain names are never stored.
- **Length hiding:** passwords are padded to 257 bytes (a `0x80` marker followed by zeros) before
  encryption.
- **Swap defense:** each record's KVS key is passed to AES-GCM as associated data.
- **Rollback defense:** `dump()` returns the SHA-256 of the serialized JSON, and `load()` checks it
  when it is given.
- **Password check:** a known constant encrypted with AES-GCM (`verifier`) must decrypt on load.
- **Serialized form:** `{ salt, verifier, kvs }`. It contains no keys, no password and no password
  hash.

The answers to the questions are in `SHORT_ANSWERS.md`.

## Web UI
```
npm run ui        # then open http://localhost:3001
```
A local demo frontend in `ui/` that uses `password-manager.js` unchanged:
- Create a vault or open a saved one. Export downloads `vault.json`, which holds the contents and
  the checksum.
- Save, reveal, copy, edit and delete passwords, and generate strong ones.
- **What gets written to disk:** the live `dump()` output, with the entry count, the fixed
  ciphertext length and the trusted checksum.
- **Attack lab:** run a swap attack, a rollback attack and a wrong-password attempt against your
  own vault, and see each one get blocked.
