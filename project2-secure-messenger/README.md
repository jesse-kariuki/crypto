# Project 2 — End-to-end Encrypted Messenger (Double Ratchet)

The implementation is in `messenger.js`, and it is the only file you submit.

## Run
```
npm install
npm test          # provided suite, including both EXTRA CREDIT tests, plus test/test-tamper.js
npm run lint
node question6code/q6code.js
```

## Design
- **Certificates:** `{ username, pub }`, where `pub` is the ElGamal (ECDH P-384) public key as a
  JWK, so the CA signature covers it. `receiveCertificate` checks the ECDSA signature.
- **Initial root key:** `RK0 = DH(my cert secret, their cert public)`. The first receiver uses its
  certificate key pair as its initial ratchet key, as in the Signal spec where Bob's signed
  prekey plays this role.
- **Root KDF:** `HKDF(dhOut, RK, "ratchet-str")` returns `[RK', CK]`.
- **Chain KDF:** `CK' = HMACtoHMACKey(CK, "chain-key")` and `MK = HMACtoAESKey(CK, "message-key")`.
- **Header:** `{ dh, pn, n, vGov, cGov, ivGov, receiverIV }`. The message is encrypted with
  AES-GCM using `JSON.stringify(header)` as the authenticated data.
- **Government escrow:** an ephemeral ElGamal key `vGov`, then
  `HMACtoAESKey(DH(eph, govPub), govEncryptionDataStr)`, and `cGov = AES-GCM(raw MK)`.
- **Replay / tampering:** a message number lower than the receiving counter throws an exception,
  and so does a failed GCM decryption. State changes are only kept if decryption succeeds, so a
  forged message cannot corrupt the session.
- **Extra credit (out-of-order):** skipped message keys are stored by `(ratchet key, n)`
  (capped by `MAX_SKIP`), as in Signal §2.6 and §3.5. Each key is deleted once used.

The answers to the questions, including the measured timings for Q6, are in `SHORT_ANSWERS.md`.

## Web UI
```
npm run ui        # then open http://localhost:3002
```
A local demo frontend in `ui/` that uses `messenger.js` unchanged. The server acts as the CA,
the government and the network for Alice, Bob and Carol.
- Side-by-side chat windows for any pair of users.
- **Message inspector:** the real header fields (`dh`, `n`, `pn`, IVs, `vGov`, `cGov`), the
  ciphertext, and what the government recovers from the escrowed key.
- **Double Ratchet state:** both sides' counters and colour-coded key fingerprints. You can
  watch the chain keys change on every message and the ratchet keys change on every DH step.
- **Intercept network:** hold messages, then deliver them out of order, flip a ciphertext bit,
  edit a header, drop a message, or replay a delivered one.
