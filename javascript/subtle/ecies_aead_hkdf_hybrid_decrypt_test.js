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

goog.module('tink.subtle.EciesAeadHkdfHybridDecryptTest');
goog.setTestOnly('tink.subtle.EciesAeadHkdfHybridDecryptTest');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const Ecdh = goog.require('tink.subtle.webcrypto.Ecdh');
const EciesAeadHkdfHybridDecrypt = goog.require('tink.subtle.EciesAeadHkdfHybridDecrypt');
const EciesAeadHkdfHybridEncrypt = goog.require('tink.subtle.EciesAeadHkdfHybridEncrypt');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const RegistryEciesAeadHkdfDemHelper = goog.require('tink.hybrid.RegistryEciesAeadHkdfDemHelper');
const TestCase = goog.require('goog.testing.TestCase');


const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  setUp() {
    AeadConfig.register();
  },

  tearDown() {
    Registry.reset();
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testNewInstance_nullParameters() {
    const keyPair = await Ecdh.generateKeyPair('P-256');
    const privateKey = await Ecdh.exportCryptoKey(keyPair.privateKey);
    const hkdfHash = 'SHA-256';
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new RegistryEciesAeadHkdfDemHelper(
        AeadKeyTemplates.aes128CtrHmacSha256());

    try {
      await EciesAeadHkdfHybridDecrypt.newInstance(
          null, hkdfHash, pointFormat, demHelper);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: Recipient private key has to be non-null.',
          e.toString());
    }

    try {
      await EciesAeadHkdfHybridDecrypt.newInstance(
          privateKey, null, pointFormat, demHelper);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: HKDF hash algorithm has to be non-null.', e.toString());
    }

    try {
      await EciesAeadHkdfHybridDecrypt.newInstance(
          privateKey, hkdfHash, null, demHelper);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: Point format has to be non-null.', e.toString());
    }

    try {
      await EciesAeadHkdfHybridDecrypt.newInstance(
          privateKey, hkdfHash, pointFormat, null);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: DEM helper has to be non-null.', e.toString());
    }
  },

  async testDecrypt_differentPamarameters_shouldWork() {
    // Set longer time for promiseTimout as the test sometimes takes longer than
    // 1 second.
    TestCase.getActiveTestCase().promiseTimeout = 5000;  // 5s
    const repetitions = 5;
    const hkdfSalt = new Uint8Array(0);

    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hmacAlgorithms = ['SHA-1', 'SHA-256', 'SHA-512'];
    const demHelper = new RegistryEciesAeadHkdfDemHelper(
        AeadKeyTemplates.aes256CtrHmacSha256());
    const curves = Object.keys(EllipticCurves.CurveType);

    // Test the encryption for different HMAC algorithms and different types of
    // curves.
    for (let hkdfHash of hmacAlgorithms) {
      for (let curve of curves) {
        const curveName =
            EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
        const keyPair = await Ecdh.generateKeyPair(curveName);

        const publicKey = await Ecdh.exportCryptoKey(keyPair.publicKey);
        const hybridEncrypt = await EciesAeadHkdfHybridEncrypt.newInstance(
            publicKey, hkdfHash, pointFormat, demHelper, hkdfSalt);

        const privateKey = await Ecdh.exportCryptoKey(keyPair.privateKey);
        const hybridDecrypt = await EciesAeadHkdfHybridDecrypt.newInstance(
            privateKey, hkdfHash, pointFormat, demHelper, hkdfSalt);

        for (let i = 0; i < repetitions; ++i) {
          const plaintext = Random.randBytes(15);
          const contextInfo = Random.randBytes(i);
          const ciphertext =
              await hybridEncrypt.encrypt(plaintext, contextInfo);
          const decryptedCiphertext =
              await hybridDecrypt.decrypt(ciphertext, contextInfo);

          assertObjectEquals(plaintext, decryptedCiphertext);
        }
      }
    }
  },

  async testEncryptDecrypt_shortCiphertext_shouldNotWork() {
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new RegistryEciesAeadHkdfDemHelper(
        AeadKeyTemplates.aes128CtrHmacSha256());
    const hkdfHash = 'SHA-512';
    const curves = Object.keys(EllipticCurves.CurveType);

    // Test that decryption fails for different types of curves.
    for (let curve of curves) {
      const curveName =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
      const keyPair = await Ecdh.generateKeyPair(curveName);
      const plaintext = Random.randBytes(10);

      const publicKey = await Ecdh.exportCryptoKey(keyPair.publicKey);
      const hybridEncrypt = await EciesAeadHkdfHybridEncrypt.newInstance(
          publicKey, hkdfHash, pointFormat, demHelper);
      const ciphertext = await hybridEncrypt.encrypt(plaintext);

      const privateKey = await Ecdh.exportCryptoKey(keyPair.privateKey);
      const hybridDecrypt = await EciesAeadHkdfHybridDecrypt.newInstance(
          privateKey, hkdfHash, pointFormat, demHelper);
      const curveEncodingSize = EllipticCurves.encodingSizeInBytes(
          EllipticCurves.CurveType[curve], pointFormat);
      try {
        await hybridDecrypt.decrypt(ciphertext.slice(0, curveEncodingSize - 1));
        fail('Should throw an exception.');
      } catch (e) {
        assertEquals('CustomError: Ciphertext is too short.', e.toString());
      }
    }
  },
});
