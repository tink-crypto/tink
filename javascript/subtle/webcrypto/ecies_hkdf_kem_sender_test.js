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

goog.module('tink.subtle.webcrypto.EciesHkdfKemSenderTest');
goog.setTestOnly('tink.subtle.webcrypto.EciesHkdfKemSenderTest');

const Bytes = goog.require('tink.subtle.Bytes');
const Ecdh = goog.require('tink.subtle.webcrypto.Ecdh');
const EciesHkdfKemSender = goog.require('tink.subtle.webcrypto.EciesHkdfKemSender');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Random = goog.require('tink.subtle.Random');
const testSuite = goog.require('goog.testing.testSuite');


testSuite({
  async testEncapsulateAlwaysGenerateRandomKey() {
    const keyPair = await Ecdh.generateKeyPair('P-256');
    const publicKey = await Ecdh.exportCryptoKey(keyPair.publicKey);
    const sender = await EciesHkdfKemSender.newInstance(publicKey);
    const keySizeInBytes = 32;
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hkdfHash = 'SHA-256';
    const hkdfInfo = Random.randBytes(32);
    const hkdfSalt = Random.randBytes(32);
    const keys = new Set();
    const tokens = new Set();
    for (let i = 0; i < 20; i++) {
      const kemKeyToken = await sender.encapsulate(
          keySizeInBytes, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      keys.add(Bytes.toHex(kemKeyToken['key']));
      tokens.add(Bytes.toHex(kemKeyToken['token']));
    }
    assertEquals(20, keys.size);
    assertEquals(20, tokens.size);
  },
  // TODO(slivova): add the following tests:
  //  * constructor with invalid parameters.
});
