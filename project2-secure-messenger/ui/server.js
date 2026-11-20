'use strict'

// Local demo server for the Double Ratchet messenger. It plays the roles of
// the certificate authority, the government and an (adversarially
// controllable) network between several MessengerClient instances.
// messenger.js and lib.js are used unchanged.

const http = require('http')
const fs = require('fs')
const path = require('path')
const { subtle } = require('node:crypto').webcrypto
const { MessengerClient } = require('../messenger')
const {
  generateEG,
  computeDH,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA,
  HMACtoAESKey,
  bufferToString,
  govEncryptionDataStr
} = require('../lib')

const PORT = process.env.PORT || 3002
const INDEX = path.join(__dirname, 'public', 'index.html')
const USERS = ['Alice', 'Bob', 'Carol']

let world = null

/** ******* Helpers ********/

function hex (buf, max) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  const s = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return max && s.length > max ? s.slice(0, max) + '…' : s
}

// Short, stable fingerprint of any extractable CryptoKey.
async function fingerprint (key) {
  if (!key) return null
  let raw
  try {
    raw = key.type === 'public' || key.type === 'private'
      ? Buffer.from(JSON.stringify(await subtle.exportKey('jwk', key)))
      : await subtle.exportKey('raw', key)
  } catch (e) {
    return 'non-extractable'
  }
  return hex(await subtle.digest('SHA-256', raw)).slice(0, 12)
}

// Same as govDecrypt in test/test-messenger.js.
async function govDecrypt (secret, [header, ct]) {
  let govKey = await computeDH(secret, header.vGov)
  govKey = await HMACtoAESKey(govKey, govEncryptionDataStr)
  const mk = await decryptWithGCM(govKey, header.cGov, header.ivGov)
  const subtleMK = await subtle.importKey('raw', mk, 'AES-GCM', true, ['encrypt', 'decrypt'])
  const plaintext = await decryptWithGCM(subtleMK, ct, header.receiverIV, JSON.stringify(header))
  return { plaintext: bufferToString(plaintext), messageKey: hex(mk) }
}

function errorText (e) {
  return typeof e === 'string' ? e : (e && e.message) || 'Operation failed'
}

async function newWorld () {
  const ca = await generateECDSA()
  const gov = await generateEG()
  const clients = {}
  const certs = {}
  for (const name of USERS) {
    clients[name] = new MessengerClient(ca.pub, gov.pub)
    const cert = await clients[name].generateCertificate(name)
    certs[name] = { cert, signature: await signWithECDSA(ca.sec, JSON.stringify(cert)) }
  }
  for (const name of USERS) {
    for (const other of USERS) {
      if (other !== name) await clients[name].receiveCertificate(certs[other].cert, certs[other].signature)
    }
  }
  return { ca, gov, clients, certs, messages: [], nextId: 1, log: [] }
}

function log (kind, text) {
  world.log.unshift({ t: Date.now(), kind, text })
  world.log = world.log.slice(0, 80)
}

async function describeHeader (header, ciphertext) {
  return {
    dh: await fingerprint(header.dh),
    pn: header.pn,
    n: header.n,
    vGov: await fingerprint(header.vGov),
    cGov: hex(header.cGov, 64),
    ivGov: hex(header.ivGov),
    receiverIV: hex(header.receiverIV),
    ciphertext: hex(ciphertext, 96),
    ciphertextBytes: ciphertext.byteLength
  }
}

async function sessionState () {
  const out = {}
  for (const name of USERS) {
    out[name] = {}
    for (const [peer, c] of Object.entries(world.clients[name].conns)) {
      out[name][peer] = {
        rootKey: await fingerprint(c.RK),
        sendChain: await fingerprint(c.CKs),
        recvChain: await fingerprint(c.CKr),
        myRatchetKey: await fingerprint(c.DHs && c.DHs.pub),
        theirRatchetKey: await fingerprint(c.DHr),
        Ns: c.Ns,
        Nr: c.Nr,
        PN: c.PN,
        skipped: Object.keys(c.MKSKIPPED).length
      }
    }
  }
  return out
}

function publicMessage (m) {
  const { header, ciphertext, ...rest } = m
  return rest
}

async function snapshot () {
  return {
    users: USERS,
    messages: world.messages.map(publicMessage),
    sessions: await sessionState(),
    log: world.log
  }
}

function findMessage (id) {
  const m = world.messages.find((x) => x.id === id)
  if (!m) throw new Error('Unknown message')
  return m
}

/** ******* Network actions ********/

async function deliver (m, mode) {
  let header = m.header
  let ciphertext = m.ciphertext
  if (mode === 'tamper-ciphertext') {
    const bytes = new Uint8Array(ciphertext.slice(0))
    bytes[0] ^= 0x01
    ciphertext = bytes.buffer
  } else if (mode === 'tamper-header') {
    header = { ...header, n: header.n + 1 }
  }

  const label = { 'tamper-ciphertext': 'tampered ciphertext', 'tamper-header': 'tampered header', replay: 'replayed copy' }[mode]
  try {
    const plaintext = await world.clients[m.to].receiveMessage(m.from, [header, ciphertext])
    if (mode === 'replay' || label) {
      log('bad', `${m.to} accepted a ${label} of #${m.id}. That should not happen!`)
      return { ok: false, plaintext }
    }
    m.status = 'delivered'
    m.receivedText = plaintext
    m.deliveredAt = Date.now()
    log('ok', `${m.to} decrypted #${m.id} from ${m.from}`)
    return { ok: true, plaintext }
  } catch (e) {
    if (label) {
      log('blocked', `${m.to} rejected a ${label} of #${m.id}: ${errorText(e)}`)
      return { ok: true, rejected: true, reason: errorText(e) }
    }
    m.status = 'failed'
    m.error = errorText(e)
    log('bad', `${m.to} could not decrypt #${m.id}: ${errorText(e)}`)
    return { ok: false, reason: errorText(e) }
  }
}

const routes = {
  async '/api/state' () {
    return await snapshot()
  },

  async '/api/reset' () {
    world = await newWorld()
    log('info', 'New world: CA and government keys generated, certificates signed and exchanged')
    return await snapshot()
  },

  async '/api/send' ({ from, to, text, autoDeliver }) {
    if (!USERS.includes(from) || !USERS.includes(to) || from === to) throw new Error('Pick two different users.')
    if (!text) throw new Error('Type a message first.')
    const [header, ciphertext] = await world.clients[from].sendMessage(to, text)
    const gov = await govDecrypt(world.gov.sec, [header, ciphertext])
    const m = {
      id: world.nextId++,
      from,
      to,
      text,
      sentAt: Date.now(),
      status: 'in-flight',
      header,
      ciphertext,
      wire: await describeHeader(header, ciphertext),
      gov
    }
    world.messages.push(m)
    log('info', `${from} encrypted #${m.id} for ${to} (chain message n=${header.n}, previous chain length pn=${header.pn})`)
    if (autoDeliver) await deliver(m)
    return await snapshot()
  },

  async '/api/deliver' ({ id, mode }) {
    const m = findMessage(id)
    if (mode === 'replay') {
      if (m.status !== 'delivered') throw new Error('Only delivered messages can be replayed.')
    } else if (m.status !== 'in-flight') {
      throw new Error('This message is no longer in flight.')
    }
    const result = await deliver(m, mode)
    return { result, ...(await snapshot()) }
  },

  async '/api/drop' ({ id }) {
    const m = findMessage(id)
    if (m.status !== 'in-flight') throw new Error('This message is no longer in flight.')
    m.status = 'dropped'
    log('info', `The network dropped #${m.id} from ${m.from} to ${m.to}`)
    return await snapshot()
  }
}

/** ******* HTTP ********/

// Messenger operations mutate shared session state, so run requests one at a time.
let queue = Promise.resolve()
function serialized (fn) {
  const run = queue.then(fn, fn)
  queue = run.catch(() => {})
  return run
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    fs.createReadStream(INDEX).pipe(res)
    return
  }

  const handler = routes[req.url]
  if (!handler || req.method !== 'POST') {
    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'Not found' }))
    return
  }

  let body = ''
  req.on('data', (chunk) => { body += chunk })
  req.on('end', () => serialized(async () => {
    let status = 200
    let payload
    try {
      if (world === null) world = await newWorld()
      payload = await handler(body ? JSON.parse(body) : {})
    } catch (e) {
      status = 400
      payload = { error: errorText(e) }
    }
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(payload))
  }))
})

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Another copy of this UI may already be running at http://localhost:${PORT}`)
    console.error('Stop it first, or pick another port, e.g.  PORT=4000 npm run ui  (PowerShell: $env:PORT=4000; npm run ui)')
    process.exit(1)
  }
  throw e
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Messenger UI running at http://localhost:${PORT}`)
})
