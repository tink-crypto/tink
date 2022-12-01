/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import 'jasmine';

import {SecurityException} from '../../../exception/security_exception';
import * as bytes from '../../../subtle/bytes';
import {randBytes} from '../../../subtle/random';

import {AesGcmHpkeAead} from './aes_gcm_hpke_aead';

interface TestVector {
  name: string;
  keyLength: 16|32;
  key: Uint8Array;
  encryptions: Array<{
    nonce: Uint8Array,
    plaintext: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array,
  }>;
}

/**
 * Test vectors as described in @see https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
 */
const TEST_VECTORS: TestVector[] = [
  {
    name: 'AES-128-GCM',
    keyLength: 16,
    key: bytes.fromHex('868c066ef58aae6dc589b6cfdd18f97e'),
    encryptions: [
      {
        nonce: bytes.fromHex('4e0bc5018beba4bf004cca59'),
        plaintext: bytes.fromHex(
            '4265617574792069732074727574682c20747275746820626561757479'),
        ciphertext: bytes.fromHex(
            '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'),
        associatedData: bytes.fromHex('436f756e742d30'),
      },
      {
        nonce: bytes.fromHex('4e0bc5018beba4bf004cca58'),
        plaintext: bytes.fromHex(
            '4265617574792069732074727574682c20747275746820626561757479'),
        ciphertext: bytes.fromHex(
            'fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06646e0329cbdf3c3cd655b28e82'),
        associatedData: bytes.fromHex('436f756e742d31'),
      },
      {
        nonce: bytes.fromHex('4e0bc5018beba4bf004cca5b'),
        plaintext: bytes.fromHex(
            '4265617574792069732074727574682c20747275746820626561757479'),
        ciphertext: bytes.fromHex(
            '895cabfac50ce6c6eb02ffe6c048bf53b7f7be9a91fc559402cbc5b8dcaeb52b2ccc93e466c28fb55fed7a7fec'),
        associatedData: bytes.fromHex('436f756e742d32'),
      },
    ]
  },
  {
    name: 'AES-256-GCM',
    keyLength: 32,
    key: bytes.fromHex(
        '751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70'),
    encryptions: [
      {
        nonce: bytes.fromHex('55ff7a7d739c69f44b25447b'),
        plaintext: bytes.fromHex(
            '4265617574792069732074727574682c20747275746820626561757479'),
        ciphertext: bytes.fromHex(
            '170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a'),
        associatedData: bytes.fromHex('436f756e742d30'),
      },
      {
        nonce: bytes.fromHex('55ff7a7d739c69f44b25447a'),
        plaintext: bytes.fromHex(
            '4265617574792069732074727574682c20747275746820626561757479'),
        ciphertext: bytes.fromHex(
            'd9ee248e220ca24ac00bbbe7e221a832e4f7fa64c4fbab3945b6f3af0c5ecd5e16815b328be4954a05fd352256'),
        associatedData: bytes.fromHex('436f756e742d31'),
      },
      {
        nonce: bytes.fromHex('55ff7a7d739c69f44b254479'),
        plaintext: bytes.fromHex(
            '4265617574792069732074727574682c20747275746820626561757479'),
        ciphertext: bytes.fromHex(
            '142cf1e02d1f58d9285f2af7dcfa44f7c3f2d15c73d460c48c6e0e506a3144bae35284e7e221105b61d24e1c7a'),
        associatedData: bytes.fromHex('436f756e742d32'),
      },
    ]
  }
];


describe('AES-GCM HPKE AEAD', () => {
  for (const testInfo of TEST_VECTORS) {
    describe('seal and open', () => {
      it(`should work for ${testInfo.name}`, async () => {
        const aead = new AesGcmHpkeAead(testInfo.keyLength);
        for (const encryption of testInfo.encryptions) {
          const ciphertext: Uint8Array = await aead.seal({
            key: testInfo.key,
            nonce: encryption.nonce,
            plaintext: encryption.plaintext,
            associatedData: encryption.associatedData,
          });

          const plaintext: Uint8Array = await aead.open({
            key: testInfo.key,
            nonce: encryption.nonce,
            ciphertext: encryption.ciphertext,
            associatedData: encryption.associatedData,
          });

          expect(ciphertext).toEqual(encryption.ciphertext);
          expect(plaintext).toEqual(encryption.plaintext);
        }
      });
    });

    describe('seal', () => {
      it(`should fail with the wrong key length for ${testInfo.name}`,
         async () => {
           const incorrectKeyLength = testInfo.keyLength === 16 ? 32 : 16;
           const aead = new AesGcmHpkeAead(incorrectKeyLength);

           await expectAsync(aead.seal({
             key: testInfo.key,
             nonce: testInfo.encryptions[0].nonce,
             plaintext: testInfo.encryptions[0].plaintext,
             associatedData: testInfo.encryptions[0].associatedData,
           })).toBeRejectedWithError(SecurityException);
         });

      it(`should generate different ciphertexts for different nonces using ${
             testInfo.name}`,
         async () => {
           const aead = new AesGcmHpkeAead(testInfo.keyLength);
           const encryption = testInfo.encryptions[0];
           const ciphertexts = new Set<string>();

           for (let i = 0; i < 10; i++) {
             const nonce: Uint8Array = randBytes(encryption.nonce.length);
             const ciphertext: Uint8Array = await aead.seal({
               key: testInfo.key,
               nonce,
               plaintext: encryption.plaintext,
               associatedData: encryption.associatedData,
             });
             const ciphertextString: string = bytes.toHex(ciphertext);
             expect(ciphertexts).not.toContain(ciphertextString);
             ciphertexts.add(ciphertextString);
           }
         });

      it(`should generate different ciphertexts for different plaintexts using ${
             testInfo.name}`,
         async () => {
           const aead = new AesGcmHpkeAead(testInfo.keyLength);
           const encryption = testInfo.encryptions[0];
           const ciphertexts = new Set<string>();

           for (let i = 0; i < 10; i++) {
             const plaintext: Uint8Array =
                 randBytes(encryption.plaintext.length);
             const ciphertext: Uint8Array = await aead.seal({
               key: testInfo.key,
               nonce: encryption.nonce,
               plaintext,
               associatedData: encryption.associatedData,
             });
             const ciphertextString: string = bytes.toHex(ciphertext);
             expect(ciphertexts).not.toContain(ciphertextString);
             ciphertexts.add(ciphertextString);
           }
         });

      it(`should generate different ciphertexts for different associated data using ${
             testInfo.name}`,
         async () => {
           const aead = new AesGcmHpkeAead(testInfo.keyLength);
           const encryption = testInfo.encryptions[0];
           const ciphertexts = new Set<string>();

           for (let i = 0; i < 10; i++) {
             const associatedData: Uint8Array =
                 randBytes(encryption.associatedData.length);
             const ciphertext: Uint8Array = await aead.seal({
               key: testInfo.key,
               nonce: encryption.nonce,
               plaintext: encryption.plaintext,
               associatedData,
             });
             const ciphertextString: string = bytes.toHex(ciphertext);
             expect(ciphertexts).not.toContain(ciphertextString);
             ciphertexts.add(ciphertextString);
           }
         });
    });

    describe('open', () => {
      it(`should fail with the wrong key length for ${testInfo.name}`,
         async () => {
           const incorrectKeyLength = testInfo.keyLength === 16 ? 32 : 16;
           const aead = new AesGcmHpkeAead(incorrectKeyLength);

           await expectAsync(aead.open({
             key: testInfo.key,
             nonce: testInfo.encryptions[0].nonce,
             ciphertext: testInfo.encryptions[0].ciphertext,
             associatedData: testInfo.encryptions[0].associatedData,
           })).toBeRejectedWithError(SecurityException);
         });

      for (const encryption of testInfo.encryptions) {
        it(`should fail with an invalid key for ${testInfo.name}`, async () => {
          const aead = new AesGcmHpkeAead(testInfo.keyLength);

          await expectAsync(aead.open({
            key: randBytes(testInfo.key.length),
            nonce: encryption.nonce,
            ciphertext: encryption.ciphertext,
            associatedData: encryption.associatedData,
          })).toBeRejectedWithError(SecurityException);
        });

        it(`should fail with an invalid nonce for ${testInfo.name}`,
           async () => {
             const aead = new AesGcmHpkeAead(testInfo.keyLength);

             await expectAsync(aead.open({
               key: testInfo.key,
               nonce: randBytes(encryption.nonce.length),
               ciphertext: encryption.ciphertext,
               associatedData: encryption.associatedData,
             })).toBeRejectedWithError(SecurityException);
           });

        it(`should fail with an invalid ciphertext for ${testInfo.name}`,
           async () => {
             const aead = new AesGcmHpkeAead(testInfo.keyLength);

             await expectAsync(aead.open({
               key: testInfo.key,
               nonce: encryption.nonce,
               ciphertext: randBytes(encryption.ciphertext.length),
               associatedData: encryption.associatedData,
             })).toBeRejectedWithError(SecurityException);
           });

        it(`should fail with invalid associated data for ${testInfo.name}`,
           async () => {
             const aead = new AesGcmHpkeAead(testInfo.keyLength);

             await expectAsync(aead.open({
               key: testInfo.key,
               nonce: encryption.nonce,
               ciphertext: encryption.ciphertext,
               associatedData: randBytes(encryption.associatedData.length),
             })).toBeRejectedWithError(SecurityException);
           });
      }
    });
  }
});
