'use strict'

// Local demo server for the password manager. It keeps one Keychain in memory
// and exposes the library API as small JSON endpoints. password-manager.js is
// used unchanged.

const http = require('http')
const fs = require('fs')
const path = require('path')
const { Keychain } = require('../password-manager')

const PORT = process.env.PORT || 3001
const INDEX = path.join(__dirname, 'public', 'index.html')

let keychain = null
let trustedChecksum = null // stands in for the user's "trusted storage"
let history = [] // previous dumps, used by the rollback demo

async function snapshot () {
  const [contents, checksum] = await keychain.dump()
  return { contents: JSON.parse(contents), raw: contents, checksum }
}

function requireKeychain () {
  if (keychain === null) throw new Error('No keychain is open. Create or load one first.')
}

function errorText (e) {
  return typeof e === 'string' ? e : (e && e.message) || 'Operation failed'
}

const routes = {
  async '/api/status' () {
    if (keychain === null) return { open: false }
    return { open: true, trustedChecksum, ...(await snapshot()) }
  },

  async '/api/init' ({ password }) {
    if (!password) throw new Error('Choose a master password.')
    keychain = await Keychain.init(password)
    history = []
    trustedChecksum = (await snapshot()).checksum
    return { open: true, trustedChecksum, ...(await snapshot()) }
  },

  async '/api/lock' () {
    keychain = null
    return { open: false }
  },

  async '/api/load' ({ password, repr, checksum }) {
    const check = checksum && checksum.trim() !== '' ? checksum.trim() : undefined
    keychain = await Keychain.load(password, repr, check)
    trustedChecksum = (await snapshot()).checksum
    return { open: true, trustedChecksum, ...(await snapshot()) }
  },

  async '/api/set' ({ name, value }) {
    requireKeychain()
    if (!name) throw new Error('Enter a site name.')
    history.push(await snapshot())
    await keychain.set(name, value)
    trustedChecksum = (await snapshot()).checksum
    return await snapshot()
  },

  async '/api/get' ({ name }) {
    requireKeychain()
    return { value: await keychain.get(name) }
  },

  async '/api/remove' ({ name }) {
    requireKeychain()
    history.push(await snapshot())
    const removed = await keychain.remove(name)
    trustedChecksum = (await snapshot()).checksum
    return { removed, ...(await snapshot()) }
  },

  // Attack lab: each attack runs against a copy of the current dump and
  // reports what the password manager did.
  async '/api/attack/swap' ({ password, a, b }) {
    requireKeychain()
    const { contents } = await snapshot()
    const keys = Object.keys(contents.kvs)
    if (keys.length < 2) throw new Error('Store at least two passwords to try a swap attack.')
    const [k1, k2] = keys
    ;[contents.kvs[k1], contents.kvs[k2]] = [contents.kvs[k2], contents.kvs[k1]]
    // Load without the trusted checksum, so only the swap defense can help.
    const tampered = await Keychain.load(password, JSON.stringify(contents))
    const results = []
    for (const name of [a, b].filter(Boolean)) {
      try {
        results.push({ name, ok: false, detail: `Returned "${await tampered.get(name)}" (attack succeeded!)` })
      } catch (e) {
        results.push({ name, ok: true, detail: errorText(e) })
      }
    }
    return { swapped: [k1, k2], results }
  },

  async '/api/attack/rollback' ({ password }) {
    requireKeychain()
    if (history.length === 0) throw new Error('Make at least one change first so there is an older version to roll back to.')
    const old = history[history.length - 1]
    try {
      await Keychain.load(password, old.raw, trustedChecksum)
      return { ok: false, detail: 'The old version loaded (attack succeeded!)' }
    } catch (e) {
      return { ok: true, detail: errorText(e) }
    }
  },

  async '/api/attack/wrongpassword' ({ password }) {
    requireKeychain()
    const { raw, checksum } = await snapshot()
    try {
      await Keychain.load(password, raw, checksum)
      return { ok: false, detail: 'Loaded with this password.' }
    } catch (e) {
      return { ok: true, detail: errorText(e) }
    }
  }
}

const server = http.createServer(async (req, res) => {
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
  req.on('end', async () => {
    let status = 200
    let payload
    try {
      payload = await handler(body ? JSON.parse(body) : {})
    } catch (e) {
      status = 400
      payload = { error: errorText(e) }
    }
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(payload))
  })
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
  console.log(`Password manager UI running at http://localhost:${PORT}`)
})
