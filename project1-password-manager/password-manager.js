"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

const SALT_LENGTH = 16;           // 128-bit salt for PBKDF2
const IV_LENGTH = 12;             // 96-bit IV, the recommended size for AES-GCM

// Every password is padded to this many bytes before encryption so that all
// ciphertexts have the same length. UTF-8 uses at most 4 bytes per character,
// and one extra byte is reserved for the padding marker.
const PADDED_LENGTH = 4 * MAX_PASSWORD_LENGTH + 1;

// Arbitrary, distinct inputs to HMAC(k, .) used to derive independent sub-keys
// from the PBKDF2 master key k.
const HMAC_KEY_LABEL = "domain-hmac-key";
const AES_KEY_LABEL = "password-aes-gcm-key";

// Known plaintext encrypted at init time; successfully decrypting it on load
// proves the supplied master password is correct.
const VERIFIER_PLAINTEXT = "keychain-password-verifier";

/********* Helper Functions ********/

/**
 * Runs PBKDF2 once on the master password and derives the two sub-keys:
 * an HMAC key for domain names and an AES-GCM key for passwords.
 */
async function deriveKeys(password, salt) {
  const rawKey = await subtle.importKey(
    "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);

  const masterKey = await subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    rawKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]);

  // Use HMAC as a PRF, evaluated at two different points, to get two
  // independent 256-bit sub-keys.
  const hmacKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer(HMAC_KEY_LABEL));
  const aesKeyMaterial = await subtle.sign("HMAC", masterKey, stringToBuffer(AES_KEY_LABEL));

  const hmacKey = await subtle.importKey(
    "raw", hmacKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const aesKey = await subtle.importKey(
    "raw", aesKeyMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);

  return { hmacKey, aesKey };
}

/**
 * Pads a password to PADDED_LENGTH bytes (ISO/IEC 7816-4 style: a 0x80
 * marker followed by zero bytes) so its length is hidden.
 */
function padPassword(value) {
  const bytes = stringToBuffer(value);
  if (bytes.length >= PADDED_LENGTH) {
    throw "Password exceeds the maximum supported length";
  }
  const padded = new Uint8Array(PADDED_LENGTH);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  return padded;
}

/** Inverse of padPassword. */
function unpadPassword(padded) {
  const bytes = new Uint8Array(padded);
  const end = bytes.lastIndexOf(0x80);
  if (end < 0) {
    throw "Invalid padding: possible tampering detected";
  }
  return bufferToString(bytes.slice(0, end));
}

/** Encrypts data with AES-GCM under a fresh random IV. */
async function encrypt(aesKey, data, additionalData) {
  const iv = getRandomBytes(IV_LENGTH);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(additionalData) }, aesKey, data);
  return { iv: encodeBuffer(iv), ct: encodeBuffer(ct) };
}

/** Decrypts an { iv, ct } record; throws if authentication fails. */
async function decrypt(aesKey, record, additionalData) {
  return await subtle.decrypt(
    { name: "AES-GCM", iv: decodeBuffer(record.iv), additionalData: stringToBuffer(additionalData) },
    aesKey,
    decodeBuffer(record.ct));
}

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *   salt:     string (Base64) - PBKDF2 salt
   *   verifier: { iv, ct }      - encryption of VERIFIER_PLAINTEXT
   *   kvs:      object          - HMAC(domain) -> { iv, ct }
   *   hmacKey:  CryptoKey       - key for HMAC over domain names
   *   aesKey:   CryptoKey       - key for AES-GCM over passwords
   * Return Type: void
   */
  constructor(salt, verifier, kvs, hmacKey, aesKey) {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      salt: salt,
      verifier: verifier,
      kvs: kvs
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      hmacKey: hmacKey,
      aesKey: aesKey
    };
  };

  /**
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const salt = getRandomBytes(SALT_LENGTH);
    const { hmacKey, aesKey } = await deriveKeys(password, salt);
    const verifier = await encrypt(aesKey, stringToBuffer(VERIFIER_PLAINTEXT), "verifier");
    return new Keychain(encodeBuffer(salt), verifier, {}, hmacKey, aesKey);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    // Rollback defense: the checksum comes from trusted storage, so any
    // change to repr (including restoring an older version) is detected.
    if (trustedDataCheck !== undefined) {
      const checksum = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(repr)));
      if (checksum !== trustedDataCheck) {
        throw "Integrity check failed: possible tampering or rollback detected";
      }
    }

    const contents = JSON.parse(repr);
    const { hmacKey, aesKey } = await deriveKeys(password, decodeBuffer(contents.salt));

    try {
      const plaintext = await decrypt(aesKey, contents.verifier, "verifier");
      if (bufferToString(plaintext) !== VERIFIER_PLAINTEXT) {
        throw "mismatch";
      }
    } catch (e) {
      throw "Invalid master password";
    }

    return new Keychain(contents.salt, contents.verifier, contents.kvs, hmacKey, aesKey);
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */
  async dump() {
    const contents = JSON.stringify(this.data);
    const checksum = encodeBuffer(await subtle.digest("SHA-256", stringToBuffer(contents)));
    return [contents, checksum];
  };

  /**
    * Computes the KVS key for a domain: the Base64 encoding of HMAC(k, name).
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async domainKey(name) {
    return encodeBuffer(await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name)));
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    const key = await this.domainKey(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, key)) {
      return null;
    }

    // Swap defense: the record was encrypted with its own KVS key as
    // associated data, so a record moved under another key fails to decrypt.
    let padded;
    try {
      padded = await decrypt(this.secrets.aesKey, this.data.kvs[key], key);
    } catch (e) {
      throw "Decryption failed: possible tampering or swap attack detected";
    }
    return unpadPassword(padded);
  };

  /**
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    const key = await this.domainKey(name);
    this.data.kvs[key] = await encrypt(this.secrets.aesKey, padPassword(value), key);
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    const key = await this.domainKey(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, key)) {
      return false;
    }
    delete this.data.kvs[key];
    return true;
  };
};

module.exports = { Keychain }
