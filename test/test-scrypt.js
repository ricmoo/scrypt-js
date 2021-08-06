"use strict";

const assert = require("assert");

const scrypt = require('../scrypt.js');

const testVectors = require('./test-vectors.json');

for (const invalid of [NaN, Infinity, -Infinity, 0.5, null]) {
  for (let i = 0; i < 4; i++) {
    const password = Buffer.from('password');
    const salt = Buffer.from('salt');
    const argname = ['N', 'r', 'p', 'dkLen'][i];
    const args = [16, 1, 1, 64];
    args[i] = invalid;
    it(`Test ${invalid} rejection ${i}`, () => assert.rejects(
      () => scrypt.scrypt(password, salt, ...args, () => {}),
      { message: `invalid ${argname}` }
    ));
  }
}

for (let i = 0; i < testVectors.length; i++) {
    const test = testVectors[i];

    const password = Buffer.from(test.password, 'hex');
    const salt = Buffer.from(test.salt, 'hex');
    const N = test.N;
    const p = test.p;
    const r = test.r;
    const dkLen = test.dkLen;

    const derivedKeyHex = test.derivedKey;

    it("Test async " + String(i), function() {
        this.timeout(60000);

        return scrypt.scrypt(password, salt, N, r, p, dkLen).then(function(key) {
            assert.equal(derivedKeyHex, Buffer.from(key).toString('hex'), 'failed to match derived key')
        }, function(error) {
            console.log(error);
            assert.ok(false);
        });
    });

    it("Test sync " + String(i), function() {
        this.timeout(60000);
        const key = scrypt.syncScrypt(password, salt, N, r, p, dkLen);
        assert.equal(derivedKeyHex, Buffer.from(key).toString('hex'), 'failed to match derived key')
    });
}

it("Test cancelling", function() {
    return assert.rejects(function() {
        return scrypt.scrypt([ 1, 2 ], [ 1, 2], (1 << 10), 8, 1, 32, function(percent) {
            if (percent >= 0.5) { return true; }
        });
    });
});

