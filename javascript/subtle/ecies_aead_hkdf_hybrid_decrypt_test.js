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
const DemHelper = goog.require('tink.hybrid.RegistryEciesAeadHkdfDemHelper');
const EciesAeadHkdfHybridDecrypt = goog.require('tink.subtle.EciesAeadHkdfHybridDecrypt');
const EciesAeadHkdfHybridEncrypt = goog.require('tink.subtle.EciesAeadHkdfHybridEncrypt');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

testSuite({
  shouldRunTests() {
    // https://msdn.microsoft.com/en-us/library/mt801195(v=vs.85).aspx
    return !userAgent.EDGE;  // b/120286783
  },

  setUp() {
    AeadConfig.register();
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    Registry.reset();
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testNewInstance_shouldWork() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const privateKey = await EllipticCurves.exportCryptoKey(keyPair.privateKey);
    const hkdfSalt = new Uint8Array(0);
    const hkdfHash = 'SHA-256';
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new DemHelper(AeadKeyTemplates.aes128CtrHmacSha256());

    await EciesAeadHkdfHybridDecrypt.newInstance(
        privateKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
  },

  async testDecrypt_shortCiphertext_shouldNotWork() {
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new DemHelper(AeadKeyTemplates.aes128CtrHmacSha256());
    const hkdfHash = 'SHA-512';
    const curve = EllipticCurves.CurveType.P256;

    const curveName = EllipticCurves.curveToString(curve);
    const curveEncodingSize =
        EllipticCurves.encodingSizeInBytes(curve, pointFormat);

    const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
    const privateKey = await EllipticCurves.exportCryptoKey(keyPair.privateKey);
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey);

    const hybridEncrypt = await EciesAeadHkdfHybridEncrypt.newInstance(
        publicKey, hkdfHash, pointFormat, demHelper);
    const hybridDecrypt = await EciesAeadHkdfHybridDecrypt.newInstance(
        privateKey, hkdfHash, pointFormat, demHelper);

    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);
    try {
      await hybridDecrypt.decrypt(ciphertext.slice(0, curveEncodingSize - 1));
      fail('Should throw an exception');
    } catch (e) {
      assertEquals('CustomError: Ciphertext is too short.', e.toString());
    }
  },

  async testDecrypt_differentDemHelpersFromOneTemplate_shouldWork() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const privateKey = await EllipticCurves.exportCryptoKey(keyPair.privateKey);
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hkdfHash = 'SHA-256';
    const keyTemplate = AeadKeyTemplates.aes256CtrHmacSha256();

    const demHelperEncrypt = new DemHelper(keyTemplate);
    const hybridEncrypt = await EciesAeadHkdfHybridEncrypt.newInstance(
        publicKey, hkdfHash, pointFormat, demHelperEncrypt);

    const demHelperDecrypt = new DemHelper(keyTemplate);
    const hybridDecrypt = await EciesAeadHkdfHybridDecrypt.newInstance(
        privateKey, hkdfHash, pointFormat, demHelperDecrypt);

    const plaintext = Random.randBytes(15);

    const ciphertext = await hybridEncrypt.encrypt(plaintext);
    const decryptedCipher = await hybridDecrypt.decrypt(ciphertext);
    assertObjectEquals(plaintext, decryptedCipher);
  },

  async testDecrypt_differentPamarameters_shouldWork() {
    const repetitions = 5;
    const hkdfSalt = new Uint8Array(0);

    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hmacAlgorithms = ['SHA-1', 'SHA-256', 'SHA-512'];
    const demHelper = new DemHelper(AeadKeyTemplates.aes256CtrHmacSha256());
    const curves = Object.keys(EllipticCurves.CurveType);

    // Test the encryption for different HMAC algorithms and different types of
    // curves.
    for (let hkdfHash of hmacAlgorithms) {
      for (let curve of curves) {
        const curveName =
            EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
        const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
        const privateKey =
            await EllipticCurves.exportCryptoKey(keyPair.privateKey);
        const publicKey =
            await EllipticCurves.exportCryptoKey(keyPair.publicKey);

        const hybridEncrypt = await EciesAeadHkdfHybridEncrypt.newInstance(
            publicKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
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
});
