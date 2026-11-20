# Project 1 — Short-answer Questions

## 1. Hiding password lengths

Before encryption, every password goes through UTF-8 encoding and then gets padded to a fixed
length of `4 * MAX_PASSWORD_LENGTH + 1 = 257` bytes. The padding is ISO/IEC 7816-4 style: a
single `0x80` marker byte follows the password, and zero bytes fill the rest. UTF-8 uses at most
4 bytes per character, so any password of up to 64 characters fits. Every plaintext has the same
length, and AES-GCM is length-preserving, so every ciphertext also has the same length (257 bytes
+ 16-byte tag). The ciphertext therefore reveals nothing about the password's length. When
decrypting, the code finds the last `0x80` byte and strips it along with everything after it.

## 2. Preventing swap attacks

Each record is stored under the key `k = Base64(HMAC(k_mac, domain))`. Its value is encrypted
with AES-GCM using **`k` itself as the associated data**. Suppose an adversary moves the record
for `www.google.com` (encrypted with AD `k_google`) to the slot `k_evil`. When `get("www.evil.com")`
runs, it decrypts that record with AD `k_evil`. AES-GCM is an authenticated encryption scheme,
so a ciphertext only decrypts with the exact AD it was created with. Forging a ciphertext that
verifies under different AD would break GCM's ciphertext integrity. So decryption fails and
`get` throws. This defense does not depend on the SHA-256 checksum, so it still works when no
trusted checksum is supplied to `load`. (`test/test-attacks.js` checks this case.)

## 3. Is a trusted location necessary for rollback defense?

Yes, some trusted state is necessary. Every value the adversary might roll back to was
produced by the honest password manager at some earlier time. That includes the MACs, the
ciphertexts, and any version counter stored inside the database. So an old database is
internally consistent and properly authenticated with the correct keys. If the client keeps no
state outside the adversary's reach, it cannot tell the "latest" database from an older valid
one. The trusted value does not have to be a full hash. A monotonic counter kept in trusted
storage, and also MAC'd into the database, would be enough. But *something* must be kept
somewhere the adversary cannot change (a hash, a counter, or a trusted server).

## 4. Lookups with a randomized MAC

With a randomized MAC, the same domain gets a different tag each time, so a tag can no longer
serve as a dictionary key. Instead, each record would store its tag (and the randomness) next to
the encrypted entry. To look up domain `x`, you go through **every** record and run
`Verify(k, x, tag_i)` until one succeeds. That makes `get`, `set` and `remove` take O(n) time
instead of O(1). The cost is a linear scan with one MAC verification per record on every
operation.

## 5. Leaking only ⌊log₂(k)⌋ of the record count

Pad the KVS with dummy records so that the number of stored entries is always the next power of
two: with `k` real records, store `2^⌈log₂ k⌉` entries in total. Each dummy entry has a random
key the same length as an HMAC output, and its value is an encryption of a padded dummy password
(or random bytes of ciphertext length). Under the PRF and CPA assumptions, dummies cannot be told
apart from real entries. When a real record is added and the count passes a power of two, the
store doubles its size with fresh dummies. When records are removed, a real entry can be
replaced by a dummy, and the store can shrink when the count drops below the previous power of
two. An observer then sees only the total entry count `2^⌈log₂ k⌉`. That reveals ⌈log₂ k⌉ and
nothing finer: any `k₁` and `k₂` with the same ⌈log₂⌉ look identical.

## 6. Multi-user support for specific sites

Give each shared site its own randomly generated key `k_site`. Store the shared password in a
separate record encrypted under `k_site`, using the same AD and padding approach. Each user then
keeps `k_site` inside their *own* keychain as an ordinary encrypted entry. Alice's keychain
stores `nytimes → k_site`, protected by her master password, and Bob's keychain does the same
under his. Either user can unwrap `k_site` with their own keys, then read or update the shared
record. Neither learns anything about the other's master password, sub-keys, or other entries,
since those are encrypted under keys derived from a different master password. The key could
also be distributed by wrapping it under each user's public key. Revoking a user means picking a
new `k_site`, re-encrypting the shared record, and re-sharing the key with the remaining users.
