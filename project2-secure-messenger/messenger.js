'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

// Only used to import the JWK public key carried in certificates.
const { subtle } = require('node:crypto').webcrypto

/** ******* Constants ********/

const ROOT_RATCHET_STR = 'ratchet-str' // HKDF info string for the root chain
const CHAIN_KEY_STR = 'chain-key' // HMAC input that advances a chain key
const MESSAGE_KEY_STR = 'message-key' // HMAC input that derives a message key
const MAX_SKIP = 1000 // upper bound on skipped message keys stored per chain

/** ******* Helpers ********/

// KDF_RK from the Signal spec: HKDF keyed by the root key over a DH output.
// Returns [new root key, new chain key].
async function kdfRK (rootKey, dhOut) {
  return await HKDF(dhOut, rootKey, ROOT_RATCHET_STR)
}

// KDF_CK from the Signal spec. Returns [next chain key, message key] where
// the message key holds both the AES-GCM CryptoKey and its raw bytes (the
// raw bytes are what gets escrowed for the government).
async function kdfCK (chainKey) {
  const nextChainKey = await HMACtoHMACKey(chainKey, CHAIN_KEY_STR)
  const messageKey = {
    key: await HMACtoAESKey(chainKey, MESSAGE_KEY_STR),
    exported: await HMACtoAESKey(chainKey, MESSAGE_KEY_STR, true)
  }
  return [nextChainKey, messageKey]
}

// Stable string identifier for an ECDH public key, used to compare ratchet
// keys and to index skipped message keys.
async function publicKeyId (publicKey) {
  const jwk = await cryptoKeyToJSON(publicKey)
  return `${jwk.x}.${jwk.y}`
}

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    this.EGKeyPair = await generateEG()
    this.username = username
    const certificate = {
      username,
      pub: await cryptoKeyToJSON(this.EGKeyPair.pub)
    }
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    const valid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!valid) {
      throw new Error('Invalid certificate signature: possible tampering detected')
    }

    // The certificate carries the public key as a JWK so the CA signature
    // covers it; import it back into a CryptoKey for DH.
    const pub = await subtle.importKey('jwk', certificate.pub,
      { name: 'ECDH', namedCurve: 'P-384' }, true, [])
    this.certs[certificate.username] = { username: certificate.username, pub }
  }

  /**
   * Creates the per-connection ratchet state. Both parties derive the same
   * initial root key from their long-term ElGamal keys:
   *   RK_0 = DH(my certificate secret, their certificate public).
   * The receiver's initial ratchet key pair is its certificate key pair, so
   * the first sender ratchets against the public key in that certificate.
   */
  async initConnection (name) {
    const cert = this.certs[name]
    if (cert === undefined) {
      throw new Error(`No certificate for ${name}`)
    }
    const rootKey = await computeDH(this.EGKeyPair.sec, cert.pub)
    this.conns[name] = {
      RK: rootKey,
      DHs: this.EGKeyPair,
      DHr: null,
      DHrId: null,
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      MKSKIPPED: {}
    }
    return this.conns[name]
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {
    const conn = this.conns[name] || await this.initConnection(name)

    // First message to this party: perform the sender's half of the initial
    // DH ratchet against their certificate key.
    if (conn.CKs === null) {
      if (conn.DHr === null) {
        conn.DHr = this.certs[name].pub
        conn.DHrId = await publicKeyId(conn.DHr)
      }
      conn.DHs = await generateEG()
      ;[conn.RK, conn.CKs] = await kdfRK(conn.RK, await computeDH(conn.DHs.sec, conn.DHr))
    }

    // Symmetric-key ratchet step: every message gets a fresh message key.
    const [nextChainKey, messageKey] = await kdfCK(conn.CKs)
    conn.CKs = nextChainKey

    // Escrow the message key for the government with ElGamal encryption:
    // an ephemeral DH with the government key, then AES-GCM.
    const govEphemeral = await generateEG()
    const govKey = await HMACtoAESKey(await computeDH(govEphemeral.sec, this.govPublicKey), govEncryptionDataStr)
    const ivGov = genRandomSalt()
    const cGov = await encryptWithGCM(govKey, messageKey.exported, ivGov)

    const header = {
      dh: conn.DHs.pub,
      pn: conn.PN,
      n: conn.Ns,
      vGov: govEphemeral.pub,
      cGov,
      ivGov,
      receiverIV: genRandomSalt()
    }
    conn.Ns += 1

    const ciphertext = await encryptWithGCM(messageKey.key, plaintext, header.receiverIV, JSON.stringify(header))
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    const committed = this.conns[name] || await this.initConnection(name)

    // Work on a copy so that a forged, replayed or corrupted message leaves
    // the stored session state untouched.
    const conn = { ...committed, MKSKIPPED: { ...committed.MKSKIPPED } }
    const dhId = await publicKeyId(header.dh)

    let messageKey
    const skippedId = `${dhId}:${header.n}`
    if (Object.prototype.hasOwnProperty.call(conn.MKSKIPPED, skippedId)) {
      // A delayed message whose key was stored when later messages arrived.
      messageKey = conn.MKSKIPPED[skippedId]
      delete conn.MKSKIPPED[skippedId]
    } else {
      if (dhId !== conn.DHrId) {
        // New ratchet public key from the other party: finish the current
        // receiving chain, then perform a DH ratchet step.
        await this.skipMessageKeys(conn, header.pn)
        conn.PN = conn.Ns
        conn.Ns = 0
        conn.Nr = 0
        conn.DHr = header.dh
        conn.DHrId = dhId
        ;[conn.RK, conn.CKr] = await kdfRK(conn.RK, await computeDH(conn.DHs.sec, conn.DHr))
        conn.DHs = await generateEG()
        ;[conn.RK, conn.CKs] = await kdfRK(conn.RK, await computeDH(conn.DHs.sec, conn.DHr))
      }
      if (header.n < conn.Nr) {
        throw new Error('Message replayed or already received')
      }
      await this.skipMessageKeys(conn, header.n)
      ;[conn.CKr, messageKey] = await kdfCK(conn.CKr)
      conn.Nr += 1
    }

    let plaintext
    try {
      plaintext = await decryptWithGCM(messageKey.key, ciphertext, header.receiverIV, JSON.stringify(header))
    } catch (e) {
      throw new Error('Decryption failed: message tampered with or not intended for this recipient')
    }

    this.conns[name] = conn
    return bufferToString(plaintext)
  }

  /**
   * Advances the receiving chain up to (but not including) message number
   * `until`, storing the skipped message keys for out-of-order delivery.
   */
  async skipMessageKeys (conn, until) {
    if (conn.CKr === null) {
      return
    }
    if (until - conn.Nr > MAX_SKIP) {
      throw new Error('Too many skipped messages')
    }
    while (conn.Nr < until) {
      let messageKey
      ;[conn.CKr, messageKey] = await kdfCK(conn.CKr)
      conn.MKSKIPPED[`${conn.DHrId}:${conn.Nr}`] = messageKey
      conn.Nr += 1
    }
  }
};

module.exports = {
  MessengerClient
}
