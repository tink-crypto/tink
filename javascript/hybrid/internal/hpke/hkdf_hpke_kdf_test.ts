/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as bytes from '../../../subtle/bytes';
import * as ellipticCurves from '../../../subtle/elliptic_curves';

import {HkdfHpkeKdf} from './hkdf_hpke_kdf';
import * as hpkeUtil from './hpke_util';

const AES_GCM_NONCE_LENGTH: number = 12;  // Nn

const TEST_VECTORS = [
  /** Test vector for DHKEM(P-256, HKDF-SHA256),HKDF-SHA256, AES-128-GCM */
  {
    macAlgorithm: 'SHA-256' as const,
    curveType: 'P-256',
    mode: hpkeUtil.BASE_MODE,
    kemId: hpkeUtil.P256_HKDF_SHA256_KEM_ID,
    kdfId: hpkeUtil.HKDF_SHA256_KDF_ID,
    aeadId: hpkeUtil.AES_128_GCM_AEAD_ID,
    aesKeyLength: 16,
    kemSharedSecretLength: 32,
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
  },
  /** Test vector for DHKEM(P-521, HKDF-SHA512),HKDF-SHA512, AES-256-GCM */
  {
    macAlgorithm: 'SHA-512' as const,
    curveType: 'P-521',
    mode: hpkeUtil.BASE_MODE,
    kemId: hpkeUtil.P521_HKDF_SHA512_KEM_ID,
    kdfId: hpkeUtil.HKDF_SHA512_KDF_ID,
    aeadId: hpkeUtil.AES_256_GCM_AEAD_ID,
    aesKeyLength: 32,
    kemSharedSecretLength: 64,
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
    keyScheduleContext: bytes.fromHex(
        '0083a27c5b2358ab4dae1b2f5d8f57f10ccccc822a473326f543f239a70aee46347324e84e02d7651a10d08fb3dda739d22d50c53fbfa8122baacd0f9ae5913072ef45baa1f3a4b169e141feb957e48d03f28c837d8904c3d6775308c3d3faa75dd64adfa44e1a1141edf9349959b8f8e5291cbdc56f62b0ed6527d692e85b09a4'),
    secret: bytes.fromHex(
        '49fd9f53b0f93732555b2054edfdc0e3101000d75df714b98ce5aa295a37f1b18dfa86a1c37286d805d3ea09a20b72f93c21e83955a1f01eb7c5eead563d21e7'),
    key: bytes.fromHex(
        '751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70'),
    baseNonce: bytes.fromHex('55ff7a7d739c69f44b25447b'),
  }
];

describe('HkdfHpkeKdf', () => {
  describe('extract', () => {
    for (const testInfo of TEST_VECTORS) {
      it('should work for ${testInfo.macAlgorithm}', async () => {
        const kdf = new HkdfHpkeKdf(testInfo.macAlgorithm);

        const suiteId: Uint8Array = hpkeUtil.hpkeSuiteId({
          kemId: testInfo.kemId,
          kdfId: testInfo.kdfId,
          aeadId: testInfo.aeadId
        });

        const defaultPskId = bytes.fromByteString('');

        const pskIdHash: Uint8Array = await kdf.labeledExtract(
            {ikm: defaultPskId, ikmLabel: 'psk_id_hash', suiteId});

        const infoHash: Uint8Array = await kdf.labeledExtract(
            {ikm: testInfo.info, ikmLabel: 'info_hash', suiteId});

        const keyScheduleContext =
            bytes.concat(testInfo.mode, pskIdHash, infoHash);

        const defaultPsk = bytes.fromByteString('');

        const secret: Uint8Array = await kdf.labeledExtract({
          ikm: defaultPsk,
          ikmLabel: 'secret',
          suiteId,
          salt: testInfo.sharedSecret
        });

        expect(keyScheduleContext).toEqual(testInfo.keyScheduleContext);
        expect(secret).toEqual(testInfo.secret);
      });
    }
  });

  describe('expand', () => {
    for (const testInfo of TEST_VECTORS) {
      it('should work for ${testInfo.macAlgorithm}', async () => {
        const kdf = new HkdfHpkeKdf(testInfo.macAlgorithm);

        const suiteId: Uint8Array = hpkeUtil.hpkeSuiteId({
          kemId: testInfo.kemId,
          kdfId: testInfo.kdfId,
          aeadId: testInfo.aeadId
        });

        const key: Uint8Array = await kdf.labeledExpand({
          prk: testInfo.secret,
          info: testInfo.keyScheduleContext,
          infoLabel: 'key',
          suiteId,
          length: testInfo.aesKeyLength,
        });

        const baseNonce: Uint8Array = await kdf.labeledExpand({
          prk: testInfo.secret,
          info: testInfo.keyScheduleContext,
          infoLabel: 'base_nonce',
          suiteId,
          length: AES_GCM_NONCE_LENGTH,
        });

        expect(key).toEqual(testInfo.key);
        expect(baseNonce).toEqual(testInfo.baseNonce);
      });
    }
  });

  describe('extractAndExpand', () => {
    for (const testInfo of TEST_VECTORS) {
      it('should work for ${testInfo.macAlgorithm}', async () => {
        const kdf = new HkdfHpkeKdf(testInfo.macAlgorithm);

        const senderPrivateKey = await hpkeUtil.getPrivateKeyFromByteArray({
          curveType: testInfo.curveType,
          publicKey: testInfo.senderPublicKey,
          privateKey: testInfo.senderPrivateKey
        });

        const recipientPublicCryptoKey =
            await hpkeUtil.getPublicKeyFromByteArray(
                testInfo.curveType, testInfo.recipientPublicKey);

        const dhSharedSecret: Uint8Array =
            await ellipticCurves.computeEcdhSharedSecret(
                senderPrivateKey, recipientPublicCryptoKey);

        const kemContext: Uint8Array =
            bytes.concat(testInfo.senderPublicKey, testInfo.recipientPublicKey);

        const sharedSecret: Uint8Array = await kdf.extractAndExpand({
          ikm: dhSharedSecret,
          ikmLabel: 'eae_prk',
          info: kemContext,
          infoLabel: 'shared_secret',
          suiteId: hpkeUtil.kemSuiteId(testInfo.kemId),
          length: testInfo.kemSharedSecretLength,
        });

        expect(sharedSecret).toEqual(testInfo.sharedSecret);
      });
    }
  });
});
