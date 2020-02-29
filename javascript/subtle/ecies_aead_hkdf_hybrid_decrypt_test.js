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

describe('ecies aead hkdf hybrid decrypt test', function() {
  beforeEach(function() {
    AeadConfig.register();
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('new instance, should work', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const privateKey = await EllipticCurves.exportCryptoKey(keyPair.privateKey);
    const hkdfSalt = new Uint8Array(0);
    const hkdfHash = 'SHA-256';
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new DemHelper(AeadKeyTemplates.aes128CtrHmacSha256());

    await EciesAeadHkdfHybridDecrypt.newInstance(
        privateKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
  });

  it('decrypt, short ciphertext, should not work', async function() {
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
      expect(e.toString()).toBe('SecurityException: Ciphertext is too short.');
    }
  });

  it('decrypt, different dem helpers from one template, should work',
     async function() {
       const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
       const privateKey =
           await EllipticCurves.exportCryptoKey(keyPair.privateKey);
       const publicKey =
           await EllipticCurves.exportCryptoKey(keyPair.publicKey);
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
       expect(decryptedCipher).toEqual(plaintext);
     });

  it('decrypt, different pamarameters, should work', async function() {
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

          expect(decryptedCiphertext).toEqual(plaintext);
        }
      }
    }
  });
});
