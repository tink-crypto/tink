/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {SecurityException} from '../../../exception/security_exception';
import * as bytes from '../../../subtle/bytes';
import * as ellipticCurves from '../../../subtle/elliptic_curves';
import {randBytes} from '../../../subtle/random';

import {AesGcmHpkeAead} from './aes_gcm_hpke_aead';
import {HkdfHpkeKdf} from './hkdf_hpke_kdf';
import {HPKE_BORINGSSL_TEST_VECTORS} from './hpke_boringssl_test_vectors';
import * as hpkeContext from './hpke_context';
import * as hpkeUtil from './hpke_util';
import {NistCurvesHpkeKem} from './nist_curves_hpke_kem';
import {fromBytes} from './nist_curves_hpke_kem_private_key';
import {parseTestVectors} from './testing/hpke_test_utils';

const
    TEST_VECTORS =
        [
          /**
           * Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
           */
          {
            mode: hpkeUtil.BASE_MODE,
            kemId: hpkeUtil.P256_HKDF_SHA256_KEM_ID,
            kdfId: hpkeUtil.HKDF_SHA256_KDF_ID,
            aeadId: hpkeUtil.AES_128_GCM_AEAD_ID,
            info: bytes.fromHex('4f6465206f6e2061204772656369616e2055726e'),
            senderPublicKey: bytes.fromHex(
                '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'),
            senderPrivateKey: bytes.fromHex(
                '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'),
            recipientPublicKey: bytes.fromHex(
                '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0'),
            recipientPrivateKey: bytes.fromHex(
                'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2'),
            encapsulatedKey: bytes.fromHex(
                '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'),
            sharedSecret: bytes.fromHex(
                'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8'),
            keyScheduleContext: bytes.fromHex(
                '00b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85'),
            secret: bytes.fromHex(
                '2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1'),
            key: bytes.fromHex('868c066ef58aae6dc589b6cfdd18f97e'),
            baseNonce: bytes.fromHex('4e0bc5018beba4bf004cca59'),
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
            ],
          },

          /**
           * Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM
           */
          {
            mode: hpkeUtil.BASE_MODE,
            kemId: hpkeUtil.P521_HKDF_SHA512_KEM_ID,
            kdfId: hpkeUtil.HKDF_SHA512_KDF_ID,
            aeadId: hpkeUtil.AES_256_GCM_AEAD_ID,
            info: bytes.fromHex('4f6465206f6e2061204772656369616e2055726e'),
            senderPublicKey: bytes.fromHex(
                '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0'),
            senderPrivateKey: bytes.fromHex(
                '014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b'),
            recipientPublicKey: bytes.fromHex(
                '0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64'),
            recipientPrivateKey: bytes.fromHex(
                '01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847'),
            encapsulatedKey: bytes.fromHex(
                '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0'),
            sharedSecret: bytes.fromHex(
                '776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818'),
            keyScheduleContext: bytes
                                    .fromHex(
                                        '0083a27c5b2358ab4dae1b2f5d8f57f10ccccc822a473326f543f239a70aee46347324e84e02d7651a10d08fb3dda739d22d50c53fbfa8122baacd0f9ae5913072ef45baa1f3a4b169e141feb957e48d03f28c837d8904c3d6775308c3d3faa75dd64adfa44e1a1141edf9349959b8f8e5291cbdc56f62b0ed6527d692e85b09a4'),
            secret: bytes.fromHex(
                '49fd9f53b0f93732555b2054edfdc0e3101000d75df714b98ce5aa295a37f1b18dfa86a1c37286d805d3ea09a20b72f93c21e83955a1f01eb7c5eead563d21e7'),
            key: bytes.fromHex(
                '751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70'),
            baseNonce: bytes.fromHex('55ff7a7d739c69f44b25447b'),
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
            ],
          },
          ...parseTestVectors(HPKE_BORINGSSL_TEST_VECTORS)
        ];

describe('HpkeContext', () => {
  for (const testInfo of TEST_VECTORS) {
    let hashFunction: 'SHA-256'|'SHA-512';
    let curveType: ellipticCurves.CurveType.P256|ellipticCurves.CurveType.P521;

    if (bytes.isEqual(testInfo.kdfId, hpkeUtil.HKDF_SHA256_KDF_ID)) {
      hashFunction = 'SHA-256';
    } else if (bytes.isEqual(testInfo.kdfId, hpkeUtil.HKDF_SHA512_KDF_ID)) {
      hashFunction = 'SHA-512';
    } else {
      throw new InvalidArgumentsException(
          `unsupported KDF id: ${testInfo.kdfId}`);
    }

    if (bytes.isEqual(testInfo.kemId, hpkeUtil.P256_HKDF_SHA256_KEM_ID)) {
      curveType = ellipticCurves.CurveType.P256;
    } else if (bytes.isEqual(
                   testInfo.kemId, hpkeUtil.P521_HKDF_SHA512_KEM_ID)) {
      curveType = ellipticCurves.CurveType.P521;
    } else {
      throw new InvalidArgumentsException(
          `unsupported KEM id: ${testInfo.kemId}`);
    }

    const kem = NistCurvesHpkeKem.fromCurve(curveType);
    const kdf = new HkdfHpkeKdf(hashFunction);
    const aead = new AesGcmHpkeAead(testInfo.key.length as 16 | 32);

    const suiteId = hpkeUtil.hpkeSuiteId({
      kemId: testInfo.kemId,
      kdfId: testInfo.kdfId,
      aeadId: testInfo.aeadId
    });

    describe('SenderAndRecipientContexts', () => {
      it(`should seal and open random messages correctly for HPKE suite id ${
             suiteId}`,
         async () => {
           const senderContext = await hpkeContext.createSenderContext(
               testInfo.recipientPublicKey, kem, kdf, aead, testInfo.info);

           const recipientKemPrivateKey = await fromBytes({
             privateKey: testInfo.recipientPrivateKey,
             publicKey: testInfo.recipientPublicKey,
             curveType
           });

           const recipientContext = await hpkeContext.createRecipientContext(
               senderContext.getEncapsulatedKey(), recipientKemPrivateKey, kem,
               kdf, aead, testInfo.info);

           const plaintext = randBytes(200);
           const aad = randBytes(100);

           const ciphertext = await senderContext.seal(plaintext, aad);
           const decrypted = await recipientContext.open(ciphertext, aad);
           expect(decrypted).toEqual(plaintext);
         });
    });

    describe('createContext', () => {
      it(`should intialize key and baseNonce correctly for HPKE suite id ${
             suiteId}`,
         async () => {
           const context = await hpkeContext.createContext(
               testInfo.encapsulatedKey, testInfo.sharedSecret, kem, kdf, aead,
               testInfo.info);

           expect(context.getKey()).toEqual(testInfo.key);
           expect(context.getBaseNonce()).toEqual(testInfo.baseNonce);
         });

      describe('seal', () => {
        const contextPromise = hpkeContext.createContext(
            testInfo.encapsulatedKey, testInfo.sharedSecret, kem, kdf, aead,
            testInfo.info);

        for (let i = 0; i < testInfo.encryptions.length; i++) {
          const encryption = testInfo.encryptions[i];

          it(`should seal correctly for HPKE suite id ${suiteId}, encryption #${
                 i}`,
             async () => {
               const context = await contextPromise;
               await expectAsync(
                   context.seal(
                       encryption.plaintext, encryption.associatedData))
                   .toBeResolvedTo(encryption.ciphertext);
             });
        }
      });

      describe('open', () => {
        let contextPromise = hpkeContext.createContext(
            testInfo.encapsulatedKey, testInfo.sharedSecret, kem, kdf, aead,
            testInfo.info);

        for (let i = 0; i < testInfo.encryptions.length; i++) {
          const encryption = testInfo.encryptions[i];

          it(`should open correctly for HPKE suite id ${suiteId}, encryption #${
                 i}`,
             async () => {
               const context = await contextPromise;
               await expectAsync(
                   context.open(
                       encryption.ciphertext, encryption.associatedData))
                   .toBeResolvedTo(encryption.plaintext);
             });
        }

        contextPromise = hpkeContext.createContext(
            testInfo.encapsulatedKey, testInfo.sharedSecret, kem, kdf, aead,
            testInfo.info);

        for (let i = 0; i < testInfo.encryptions.length; i++) {
          const encryption = testInfo.encryptions[i];
          const wrongAssociatedData =
              randBytes(encryption.associatedData.length);

          it(`should fail with an incorrect associated data for HPKE suite id ${
                 suiteId}, encryption #${i}`,
             async () => {
               const context = await contextPromise;

               await expectAsync(
                   context.open(encryption.ciphertext, wrongAssociatedData))
                   .toBeRejectedWithError(SecurityException);
             });
        }

        contextPromise = hpkeContext.createContext(
            testInfo.encapsulatedKey, testInfo.sharedSecret, kem, kdf, aead,
            testInfo.info);

        for (let i = 0; i < testInfo.encryptions.length; i++) {
          const encryption = testInfo.encryptions[i];
          const wrongCiphertext = randBytes(encryption.ciphertext.length);

          it(`should fail with an incorrect ciphertext but correct associated data for HPKE suite id ${
                 suiteId}, encryption #${i}`,
             async () => {
               const context = await contextPromise;
               await expectAsync(
                   context.open(wrongCiphertext, encryption.associatedData))
                   .toBeRejectedWithError(SecurityException);
             });
        }
      });
    });
  }
});
