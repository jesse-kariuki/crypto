"use strict";

let expect = require('expect.js');
const { Keychain } = require('../password-manager');

function expectReject(promise) {
    return promise.then(
        (result) => expect().fail(`Expected failure, but function returned ${result}`),
        (error) => {},
    );
}

describe('Password manager attacks', async function() {
    this.timeout(5000);
    let password = "password123!";

    it('detects a swap attack even without a trusted checksum', async function() {
        let keychain = await Keychain.init(password);
        await keychain.set('www.google.com', 'googlepw');
        await keychain.set('www.evil.com', 'evilpw');
        let contents = JSON.parse((await keychain.dump())[0]);
        let [k1, k2] = Object.keys(contents.kvs);
        [contents.kvs[k1], contents.kvs[k2]] = [contents.kvs[k2], contents.kvs[k1]];
        let swapped = await Keychain.load(password, JSON.stringify(contents));
        await expectReject(swapped.get('www.google.com'));
        await expectReject(swapped.get('www.evil.com'));
    });

    it('detects a rollback attack with the trusted checksum', async function() {
        let keychain = await Keychain.init(password);
        await keychain.set('www.google.com', 'oldpw');
        let oldContents = (await keychain.dump())[0];
        await keychain.set('www.google.com', 'newpw');
        let newChecksum = (await keychain.dump())[1];
        await expectReject(Keychain.load(password, oldContents, newChecksum));
    });

    it('produces ciphertexts of equal length for different password lengths', async function() {
        let keychain = await Keychain.init(password);
        await keychain.set('a', '');
        await keychain.set('b', 'x'.repeat(64));
        let kvs = JSON.parse((await keychain.dump())[0]).kvs;
        let lengths = Object.values(kvs).map((r) => r.ct.length);
        expect(lengths[0]).to.equal(lengths[1]);
        expect(await keychain.get('b')).to.equal('x'.repeat(64));
        expect(await keychain.get('a')).to.equal('');
    });

    it('updates an existing password and round-trips unicode', async function() {
        let keychain = await Keychain.init(password);
        await keychain.set('site', 'first');
        await keychain.set('site', 'pässwörd-🔑');
        expect(await keychain.get('site')).to.equal('pässwörd-🔑');
    });
});
