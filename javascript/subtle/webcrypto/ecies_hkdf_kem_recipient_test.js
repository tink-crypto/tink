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

goog.module('tink.subtle.webcrypto.EciesHkdfKemRecipientTest');
goog.setTestOnly('tink.subtle.webcrypto.EciesHkdfKemRecipientTest');

const Bytes = goog.require('tink.subtle.Bytes');
const Ecdh = goog.require('tink.subtle.webcrypto.Ecdh');
const EciesHkdfKemRecipient = goog.require('tink.subtle.webcrypto.EciesHkdfKemRecipient');
const EciesHkdfKemSender = goog.require('tink.subtle.webcrypto.EciesHkdfKemSender');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Random = goog.require('tink.subtle.Random');
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');


testSuite({

  tearDown() {
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testEncapDecap() {
    // Set longer time for promiseTimout as the test sometimes takes longer than
    // 1 second in Firefox.
    TestCase.getActiveTestCase().promiseTimeout = 5000;  // 5s
    const keyPair = await Ecdh.generateKeyPair('P-256');
    const publicKey = await Ecdh.exportCryptoKey(keyPair.publicKey);
    const privateKey = await Ecdh.exportCryptoKey(keyPair.privateKey);
    const sender = await EciesHkdfKemSender.newInstance(publicKey);
    const recipient = await EciesHkdfKemRecipient.newInstance(privateKey);
    for (let i = 1; i < 20; i++) {
      const keySizeInBytes = i;
      const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
      const hkdfHash = 'SHA-256';
      const hkdfInfo = Random.randBytes(i);
      const hkdfSalt = Random.randBytes(i);

      const kemKeyToken = await sender.encapsulate(
          keySizeInBytes, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      const key = await recipient.decapsulate(
          kemKeyToken['token'], keySizeInBytes, pointFormat, hkdfHash, hkdfInfo,
          hkdfSalt);

      assertEquals(keySizeInBytes, kemKeyToken['key'].length);
      assertEquals(Bytes.toHex(key), Bytes.toHex(kemKeyToken['key']));
    }
  },

  // TODO(slivova): add the following tests:
  //  * constructor with invalid parameters.
  //  * decapsulate with modified token or other parameters.
  //  * decapsulate with test vectors produced by Java implementation.
});
