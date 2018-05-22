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
const array = goog.require('goog.array');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testBasic: function() {
    const key = Random.randBytes(16);
    const results = new Set();
    for (let i = 0; i < 100; i++) {
      const msg = Random.randBytes(20);
      const aesctr = new AesCtr(key, 16);
      let ciphertext = aesctr.encrypt(msg);
      assertEquals(Bytes.toHex(msg), Bytes.toHex(aesctr.decrypt(ciphertext)));
      results.add(Bytes.toHex(ciphertext));
    }
    assertEquals(100, results.size);
  },

  testConstructor: function() {
    assertThrows(function() {
      new AesCtr(Random.randBytes(16), 11);  // IV size too short
    });
    assertThrows(function() {
      new AesCtr(Random.randBytes(16), 17);  // IV size too long
    });
    assertThrows(function() {
      new AesCtr(Random.randBytes(24), 12);  // 192-bit keys not supported
    });
  },

  testWithTestVectors: function() {
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
    array.forEach(NIST_TEST_VECTORS, function(testVector) {
      const key = Bytes.fromHex(testVector.key);
      const iv = Bytes.fromHex(testVector.iv);
      const plaintext = Bytes.fromHex(testVector.message);
      const ciphertext = Bytes.fromHex(testVector.ciphertext);
      const aesctr = new AesCtr(key, iv.length);
      assertEquals(
          Bytes.toHex(plaintext),
          Bytes.toHex(aesctr.decrypt(Bytes.concat(iv, ciphertext))));
    });
  },
});
