// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.subtle.AesCtrTest');
goog.setTestOnly('tink.subtle.AesCtrTest');

const AesCtr = goog.require('tink.subtle.AesCtr');
const Bytes = goog.require('tink.subtle.Bytes');
const Random = goog.require('tink.subtle.Random');
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({

  setUp() {
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    // Reset the timeout.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testBasic() {
    // Set longer time for promiseTimout as the test sometimes takes longer than
    // 1 second in Firefox.
    const key = Random.randBytes(16);
    for (let i = 0; i < 100; i++) {
      const msg = Random.randBytes(20);
      const cipher = await AesCtr.newInstance(key, 16);
      let ciphertext = await cipher.encrypt(msg);
      let plaintext = await cipher.decrypt(ciphertext);
      assertEquals(Bytes.toHex(msg), Bytes.toHex(plaintext));
    }
  },

  async testProbabilisticEncryption() {
    const cipher = await AesCtr.newInstance(Random.randBytes(16), 16);
    const msg = Random.randBytes(20);
    const results = new Set();
    for (let i = 0; i < 100; i++) {
      const ciphertext = await cipher.encrypt(msg);
      results.add(Bytes.toHex(ciphertext));
    }
    assertEquals(100, results.size);
  },

  async testConstructor() {
    try {
      await AesCtr.newInstance(Random.randBytes(16), 11);  // IV size too short
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid IV length, must be at least 12 and at most 16',
          e.toString());
    }
    try {
      await AesCtr.newInstance(Random.randBytes(16), 17);  // IV size too long
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid IV length, must be at least 12 and at most 16',
          e.toString());
    }
    try {
      await AesCtr.newInstance(
          Random.randBytes(24), 12);  // 192-bit keys not supported
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: unsupported AES key size: 24', e.toString());
    }
  },

  async testConstructor_invalidIvSizes() {
    try {
      await AesCtr.newInstance(Random.randBytes(16), NaN);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid IV length, must be an integer', e.toString());
    }

    try {
      await AesCtr.newInstance(Random.randBytes(16), 12.5);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid IV length, must be an integer', e.toString());
    }

    try {
      await AesCtr.newInstance(Random.randBytes(16), 0);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: invalid IV length, must be at least 12 and at most 16',
          e.toString());
    }
  },

  async testWithTestVectors() {
    // Test data from NIST SP 800-38A pp 55.
    const NIST_TEST_VECTORS = [
      {
        'key': '2b7e151628aed2a6abf7158809cf4f3c',
        'message':
            '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51' +
            '30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
        'ciphertext':
            '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff' +
            '5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee',
        'iv': 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
      },
    ];
    for (let i = 0; i < NIST_TEST_VECTORS.length; i++) {
      const testVector = NIST_TEST_VECTORS[i];
      const key = Bytes.fromHex(testVector['key']);
      const iv = Bytes.fromHex(testVector['iv']);
      const msg = Bytes.fromHex(testVector['message']);
      const ciphertext = Bytes.fromHex(testVector['ciphertext']);
      const aesctr = await AesCtr.newInstance(key, iv.length);
      const plaintext = await aesctr.decrypt(Bytes.concat(iv, ciphertext));
      assertEquals(Bytes.toHex(msg), Bytes.toHex(plaintext));
    }
  },
});
