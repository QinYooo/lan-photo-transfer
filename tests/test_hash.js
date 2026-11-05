'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { SHA256 } = require('../static/hash.js');
let count = 0;
for (const length of [0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 129, 1000, 1024*1024-1, 1024*1024, 1024*1024+1]) {
  const data = crypto.randomBytes(length);
  const expected = crypto.createHash('sha256').update(data).digest('hex');
  for (const step of [1, 7, 63, 64, 73, 1024*1024]) {
    const hash = new SHA256();
    for (let i=0; i<data.length; i+=step) hash.update(data.subarray(i,i+step));
    assert.equal(hash.digestHex(), expected, `length=${length}, step=${step}`);
    count++;
  }
}
// SHA-256 encodes bit length in 64 bits; >512 MiB crosses the low-word boundary.
const block = Buffer.alloc(1024*1024, 0xa5);
const actual = new SHA256(), expected = crypto.createHash('sha256');
for (let i=0; i<513; i++) { actual.update(block); expected.update(block); }
assert.equal(actual.digestHex(), expected.digest('hex'));
console.log(`PASS: ${count} random boundary/chunk cases plus 513 MiB streamed length test`);
