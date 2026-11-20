# Project 2 — Short-answer Questions

## 1. Ratcheting DH only every ten messages

Yes. Confidentiality against a passive eavesdropper would be preserved. Every message is still
encrypted under a fresh message key from the symmetric-key (KDF chain) ratchet. Those keys
are PRF outputs that look pseudorandom to anyone who does not know the chain key, so semantic
security holds no matter how often the DH ratchet runs. The trade-off is weaker break-in
recovery: after a compromise, the attacker can read up to ten messages (until the next DH
ratchet) instead of only those before the next reply. Forward secrecy for earlier messages still
comes from the one-way chain ratchet.

## 2. Never updating the DH keys

All keys would then come from a single, unchanging sending chain and receiving chain.
- **Forward secrecy** is partly kept. The KDF chain is one-way, so an attacker who steals the
  current chain key cannot compute *earlier* message keys. But an attacker who steals the
  long-term DH secrets can recompute the root key and the entire chain from the start, so all
  past messages become readable.
- **Break-in recovery** is lost entirely. Without fresh DH contributions, a stolen chain key lets
  the attacker derive every *future* message key forever. No new secret ever enters the state
  that the attacker does not already know.

## 3. Longest sending chains

A new sending chain starts each time a party sends right after receiving (that is, after a DH
ratchet step).
- **Alice:** her first chain carries "Hey Bob…" and "I need to get my laptop", which is **2**
  messages. After Bob's reply she ratchets, and her next chain carries only "Great, thanks!…"
  (1 message). **The longest is 2.**
- **Bob:** "Sure, it's 1234!" is the only message on his first chain, and "Did it work?" is the
  only message on his second (a new chain after receiving Alice's message). **The longest is 1.**

## 4. Mallory steals Alice's keys before her third message

The relevant property is **forward secrecy**. Bob's "Sure, it's 1234!" was encrypted with a
message key from Bob's sending chain. That chain comes from the root key and the DH output
`DH(bob_ratchet_sec, alice_ratchet_pub_1)`. When Alice received the message, she derived the
message key, decrypted, and then **deleted** it. She then ran a DH ratchet step with a fresh key
pair and replaced the old root and chain keys with new ones. What Mallory steals is Alice's
*current* state: the new root key, her new ratchet secret, and the new chain keys. Recovering the
old message key would mean inverting HKDF/HMAC (the one-way root and chain KDFs) or solving the
DH problem for the old ratchet keys, whose secret halves are gone. So Mallory cannot decrypt the
recorded ciphertext and does not learn the combination.

## 5. Problems with the government escrow scheme

- **Single point of catastrophic failure.** One government secret key decrypts *every* message
  from every user, past and future. If it leaks, is stolen, or is abused by an insider, all
  confidentiality across the whole system is lost at once, retroactively. Forward secrecy and
  break-in recovery do not protect against this.
- **Abuse and mission creep.** Nothing technical limits use to lawful, targeted requests. Bulk
  surveillance is easy, and other governments or criminals will want or steal the same access.
- **Easy to evade.** Criminals can encrypt their messages again on top, use a modified client
  that puts garbage in `cGov` (the recipient never checks it), use steganography, or use a
  foreign app. So the scheme mostly watches law-abiding users.
- **Bigger attack surface and loss of trust.** Escrow adds complexity, and so more room for bugs.
  It also undermines user trust and the reasons people choose E2EE in the first place.

## 6. ECDSA vs RSA (measured with `question6code/q6code.js`, Node v22)

| Operation | RSA-PSS 4096 | ECDSA P-384 |
|---|---|---|
| Key generation | 1.508 s | 2.85 ms |
| Sign | 12.92 ms | 2.32 ms |
| Verify | 0.94 ms | 1.78 ms |
| Signature length | 512 bytes | 96 bytes |

- **(a) Key generation:** RSA takes much longer. It must find two large random primes, which
  takes many primality tests. An ECDSA key is just a random scalar and one point multiplication.
- **(b) Signing:** RSA takes longer. It needs a 4096-bit modular exponentiation with the large
  private exponent (sped up with CRT), while ECDSA does one scalar multiplication on a 384-bit
  curve.
- **(c) Signature length:** RSA signatures are longer. They are as long as the modulus (512 bytes),
  while an ECDSA signature is two 48-byte integers `(r, s)`, 96 bytes in total.
- **(d) Verification:** ECDSA takes longer. RSA verification uses the small public exponent
  e = 65537 (only 17 modular squarings and multiplications), while ECDSA verification needs two
  scalar multiplications.
