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
  async testEncapsulate_alwaysGenerateRandomKey() {
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

  async testNewInstance_invalidParameters() {
    // Test newInstance without key.
    try {
      await EciesHkdfKemSender.newInstance(null);
      fail('An exception should be thrown.');
    } catch (e) {
    }

    // Test newInstance with public key instead private key.
    const keyPair = await Ecdh.generateKeyPair('P-256');
    const privateKey = await Ecdh.exportCryptoKey(keyPair.privateKey);
    try {
      await EciesHkdfKemSender.newInstance(privateKey);
      fail('An exception should be thrown.');
    } catch (e) {
    }

    // Test newInstance with CryptoKey instead of JSON key.
    try {
      await EciesHkdfKemSender.newInstance(keyPair.publicKey);
      fail('An exception should be thrown.');
    } catch (e) {
    }
  },

  async testNewInstance_invalidPublicKey() {
    for (let crv of Object.keys(EllipticCurves.CurveType)) {
      const curve = EllipticCurves.CurveType[crv];
      const crvString = EllipticCurves.curveToString(curve);
      const keyPair = await Ecdh.generateKeyPair(crvString);
      const publicJwk = await Ecdh.exportCryptoKey(keyPair.publicKey);
      // Change the 'x' value to make the public key invalid. Either getting new
      // recipient with corrupted public key or trying to encapsulate with this
      // recipient should fail.
      const xLength = EllipticCurves.fieldSizeInBytes(curve);
      publicJwk['x'] =
          Bytes.toBase64(new Uint8Array(xLength), /* opt_webSafe = */ true);
      const hkdfInfo = Random.randBytes(10);
      const salt = Random.randBytes(8);
      try {
        const sender = await EciesHkdfKemSender.newInstance(publicJwk);
        await sender.encapsulate(
            /* keySizeInBytes = */ 32,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            /* hkdfHash = */ 'SHA-256', hkdfInfo, salt);
        fail('Should throw an exception.');
      } catch (e) {
      }
    }
  },

  async testConstructor_invalidParameters() {
    // Test constructor without key.
    try {
      new EciesHkdfKemSender(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: Recipient public key has to be non-null.',
          e.toString());
    }

    // Test constructor with public key instead private key.
    const keyPair = await Ecdh.generateKeyPair('P-256');
    try {
      new EciesHkdfKemSender(keyPair.privateKey);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: Expected Crypto key of type: public.', e.toString());
    }

    // Test that JSON key cannot be used instead of CryptoKey.
    const publicKey = await Ecdh.exportCryptoKey(keyPair.publicKey);
    try {
      new EciesHkdfKemSender(publicKey);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: Expected Crypto key of type: public.', e.toString());
    }
  },
});
