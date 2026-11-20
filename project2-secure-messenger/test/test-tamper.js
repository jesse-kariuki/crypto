'use strict'

/* global describe it before */

const { MessengerClient } = require('../messenger.js')
const { generateEG, generateECDSA, signWithECDSA } = require('../lib.js')

const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')

chai.use(chaiAsPromised)
const expect = chai.expect

describe('Messenger tampering', function () {
  this.timeout(5000)
  let caKeyPair, govKeyPair

  before(async function () {
    caKeyPair = await generateECDSA()
    govKeyPair = await generateEG()
  })

  async function setup () {
    const alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub)
    const bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub)
    const aliceCert = await alice.generateCertificate('alice')
    const bobCert = await bob.generateCertificate('bob')
    await alice.receiveCertificate(bobCert, await signWithECDSA(caKeyPair.sec, JSON.stringify(bobCert)))
    await bob.receiveCertificate(aliceCert, await signWithECDSA(caKeyPair.sec, JSON.stringify(aliceCert)))
    return { alice, bob }
  }

  it('rejects a modified ciphertext and keeps the session usable', async function () {
    const { alice, bob } = await setup()
    const [header, ct] = await alice.sendMessage('bob', 'secret')
    const forged = new Uint8Array(ct.slice(0))
    forged[0] ^= 1
    await expect(bob.receiveMessage('alice', [header, forged.buffer])).to.be.rejected
    expect(await bob.receiveMessage('alice', [header, ct])).to.equal('secret')
  })

  it('rejects a modified header field', async function () {
    const { alice, bob } = await setup()
    const [header, ct] = await alice.sendMessage('bob', 'secret')
    await expect(bob.receiveMessage('alice', [{ ...header, pn: header.pn + 1 }, ct])).to.be.rejected
  })

  it('rejects a certificate whose public key was swapped', async function () {
    const { alice } = await setup()
    const mallory = new MessengerClient(caKeyPair.pub, govKeyPair.pub)
    const carol = new MessengerClient(caKeyPair.pub, govKeyPair.pub)
    const carolCert = await carol.generateCertificate('carol')
    const sig = await signWithECDSA(caKeyPair.sec, JSON.stringify(carolCert))
    const malloryCert = await mallory.generateCertificate('carol')
    await expect(alice.receiveCertificate(malloryCert, sig)).to.be.rejected
  })
})
