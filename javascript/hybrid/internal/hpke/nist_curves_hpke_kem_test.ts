/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import * as bytes from '../../../subtle/bytes';
import * as ellipticCurves from '../../../subtle/elliptic_curves';

import {HPKE_BORINGSSL_TEST_VECTORS} from './hpke_boringssl_test_vectors';
import {HpkeKemEncapOutput} from './hpke_kem_encap_output';
import * as hpkeUtil from './hpke_util';
import {NistCurvesHpkeKem} from './nist_curves_hpke_kem';
import {fromBytes} from './nist_curves_hpke_kem_private_key';
import {parseTestVectors} from './testing/hpke_test_utils';

interface TestVector {
  kemId: Uint8Array;
  senderPublicKey: Uint8Array;
  senderPrivateKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  recipientPrivateKey: Uint8Array;
  encapsulatedKey: Uint8Array;
  sharedSecret: Uint8Array;
}

/**
 * Test vectors as described in @see https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
 */
const TEST_VECTORS: TestVector[] = [
  /** Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM */
  {
    kemId: hpkeUtil.P256_HKDF_SHA256_KEM_ID,
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
  },
  /** Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM */
  {
    kemId: hpkeUtil.P521_HKDF_SHA512_KEM_ID,
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
  },
  ...parseTestVectors(HPKE_BORINGSSL_TEST_VECTORS)
];

describe('NIST curves HPKE KEM', () => {
  for (const testInfo of TEST_VECTORS) {
    let curveType: ellipticCurves.CurveType.P256|ellipticCurves.CurveType.P521;

    if (bytes.isEqual(testInfo.kemId, hpkeUtil.P256_HKDF_SHA256_KEM_ID)) {
      curveType = ellipticCurves.CurveType.P256;
    } else if (bytes.isEqual(
                   testInfo.kemId, hpkeUtil.P521_HKDF_SHA512_KEM_ID)) {
      curveType = ellipticCurves.CurveType.P521;
    } else {
      throw new InvalidArgumentsException(
          `unsupported KEM id: ${testInfo.kemId}`);
    }

    const curveString = ellipticCurves.curveToString(curveType);
    describe('encapsulate', () => {
      it(`should work for ${curveString}`, async () => {
        const kem: NistCurvesHpkeKem = NistCurvesHpkeKem.fromCurve(curveType);

        const senderPrivateKeyPair = await fromBytes({
          privateKey: testInfo.senderPrivateKey,
          publicKey: testInfo.senderPublicKey,
          curveType,
        });

        // use the encapsulateHelper test only function
        const result: HpkeKemEncapOutput = await kem.TEST_ONLY(
            testInfo.recipientPublicKey, senderPrivateKeyPair);

        expect(result.sharedSecret).toEqual(testInfo.sharedSecret);
        expect(result.encapsulatedKey).toEqual(testInfo.encapsulatedKey);
      });

      it(`should fail with an invalid ${curveString} recipient public key`,
         async () => {
           const kem = NistCurvesHpkeKem.fromCurve(curveType);

           const senderPrivateKeyPair = await fromBytes({
             privateKey: testInfo.senderPrivateKey,
             publicKey: testInfo.senderPublicKey,
             curveType,
           });

           const invalidRecipientPublicKey =
               bytes.concat(testInfo.recipientPublicKey, new Uint8Array(2));

           await expectAsync(
               kem.TEST_ONLY(invalidRecipientPublicKey, senderPrivateKeyPair))
               .toBeRejectedWithError(InvalidArgumentsException);
         });

      it(`should fail with a mismatched curve type for ${curveString}`,
         async () => {
           const mismatchedCurveType =
               curveType === ellipticCurves.CurveType.P256 ?
               ellipticCurves.CurveType.P521 :
               ellipticCurves.CurveType.P256;

           const kem = NistCurvesHpkeKem.fromCurve(mismatchedCurveType);

           await expectAsync(kem.encapsulate(testInfo.recipientPublicKey))
               .toBeRejectedWithError(InvalidArgumentsException);
         });

      it(`should not encapsulate the correct sharedSecret nor escapsulatedKey with a mismatched senderPrivateKeyPair for ${
             curveString}`,
         async () => {
           const kem = NistCurvesHpkeKem.fromCurve(curveType);

           // use recipientPrivateKeyPair as the senderPrivateKeyPair"
           const recipientPrivateKeyPair = await fromBytes({
             privateKey: testInfo.recipientPrivateKey,
             publicKey: testInfo.recipientPublicKey,
             curveType,
           });

           const result: HpkeKemEncapOutput = await kem.TEST_ONLY(
               testInfo.recipientPublicKey, recipientPrivateKeyPair);

           expect(result.sharedSecret).not.toEqual(testInfo.sharedSecret);
           expect(result.encapsulatedKey).not.toEqual(testInfo.encapsulatedKey);
         });
    });

    describe('decapsulate', () => {
      it(`should work for ${curveString}`, async () => {
        const kem = NistCurvesHpkeKem.fromCurve(curveType);

        const recipientPrivateKeyPair = await fromBytes({
          privateKey: testInfo.recipientPrivateKey,
          publicKey: testInfo.recipientPublicKey,
          curveType,
        });

        const result: Uint8Array = await kem.decapsulate(
            testInfo.encapsulatedKey, recipientPrivateKeyPair);
        expect(result).toEqual(testInfo.sharedSecret);
      });

      it(`should fail with an invalid ${curveString} encapsulated key`,
         async () => {
           const kem = NistCurvesHpkeKem.fromCurve(curveType);

           const recipientPrivateKeyPair = await fromBytes({
             privateKey: testInfo.recipientPrivateKey,
             publicKey: testInfo.recipientPublicKey,
             curveType,
           });

           const invalidEncapsulatedKey =
               bytes.concat(testInfo.encapsulatedKey, new Uint8Array(2));

           await expectAsync(
               kem.decapsulate(invalidEncapsulatedKey, recipientPrivateKeyPair))
               .toBeRejectedWithError(InvalidArgumentsException);
         });

      it(`should fail with a mismatched curve type for ${curveString}`,
         async () => {
           const mismatchedCurveType =
               curveType === ellipticCurves.CurveType.P256 ?
               ellipticCurves.CurveType.P521 :
               ellipticCurves.CurveType.P256;

           const kem = NistCurvesHpkeKem.fromCurve(mismatchedCurveType);

           const recipientPrivateKeyPair = await fromBytes({
             privateKey: testInfo.recipientPrivateKey,
             publicKey: testInfo.recipientPublicKey,
             curveType,
           });

           await expectAsync(
               kem.decapsulate(
                   testInfo.encapsulatedKey, recipientPrivateKeyPair))
               .toBeRejectedWithError(InvalidArgumentsException);
         });

      it(`should not decapsulate the correct sharedSecret with a mismatched recipientPrivateKeyPair for ${
             curveString}`,
         async () => {
           const kem = NistCurvesHpkeKem.fromCurve(curveType);

           // use senderPrivateKeyPair as the recipientPrivateKeyPair"
           const senderPrivateKeyPair = await fromBytes({
             privateKey: testInfo.senderPrivateKey,
             publicKey: testInfo.senderPublicKey,
             curveType,
           });

           const result: Uint8Array = await kem.decapsulate(
               testInfo.encapsulatedKey, senderPrivateKeyPair);

           expect(result).not.toEqual(testInfo.sharedSecret);
         });
    });
  }
});
