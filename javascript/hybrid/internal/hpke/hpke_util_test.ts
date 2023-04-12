/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {SecurityException} from '../../../exception/security_exception';
import {PbHpkeKem} from '../../../internal/proto';
import * as bytes from '../../../subtle/bytes';
import * as ellipticCurves from '../../../subtle/elliptic_curves';
import {randBytes} from '../../../subtle/random';

import * as hpkeUtil from './hpke_util';

/**
 * Test vectors as described in @see https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
 */
const TEST_VECTORS = [
  /** Sender keys for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM */
  {
    name: 'sender DHKEM(P-256, HKDF-SHA256)',
    curveType: 'P-256',
    publicKey: bytes.fromHex(
        '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'),
    privateKey: bytes.fromHex(
        '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'),
  },
  /** Recipient keys for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM */
  {
    name: 'recipient DHKEM(P-256, HKDF-SHA256)',
    curveType: 'P-256',
    publicKey: bytes.fromHex(
        '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0'),
    privateKey: bytes.fromHex(
        'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2'),
  },
  /** Sender keys for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM */
  {
    name: 'sender DHKEM(P-521, HKDF-SHA512)',
    curveType: 'P-521',
    publicKey: bytes.fromHex(
        '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0'),
    privateKey: bytes.fromHex(
        '014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b'),
  },
  /** Recipient keys for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM */
  {
    name: 'recipient DHKEM(P-521, HKDF-SHA512)',
    curveType: 'P-521',
    publicKey: bytes.fromHex(
        '0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64'),
    privateKey: bytes.fromHex(
        '01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847'),
  },
];

describe('HPKE Util', () => {
  for (const testInfo of TEST_VECTORS) {
    it(`should convert ${testInfo.name} public key bytes to CryptoKey and back`,
       async () => {
         const asCryptoKey: CryptoKey =
             await hpkeUtil.getPublicKeyFromByteArray(
                 testInfo.curveType, testInfo.publicKey);

         expect(asCryptoKey.type).toEqual('public');
         const alg: EcKeyGenParams = asCryptoKey.algorithm as EcKeyGenParams;
         expect(alg.name).toEqual('ECDH');
         expect(alg.namedCurve).toEqual(testInfo.curveType);

         const asByteArray: Uint8Array =
             await hpkeUtil.getByteArrayFromPublicKey(asCryptoKey);

         expect(asByteArray).toEqual(testInfo.publicKey);
       });

    it(`should convert ${
           testInfo.name} private key bytes to CryptoKey and back`,
       async () => {
         const asCryptoKey: CryptoKey =
             await hpkeUtil.getPrivateKeyFromByteArray({
               curveType: testInfo.curveType,
               publicKey: testInfo.publicKey,
               privateKey: testInfo.privateKey
             });

         expect(asCryptoKey.type).toEqual('private');
         const alg: EcKeyGenParams = asCryptoKey.algorithm as EcKeyGenParams;
         expect(alg.name).toEqual('ECDH');
         expect(alg.namedCurve).toEqual(testInfo.curveType);

         /* Since we cannot retrieve the private key bytes from a CryptoKey, we
          * only compare the public key bytes. */
         const asByteArray: Uint8Array =
             await hpkeUtil.getByteArrayFromPublicKey(asCryptoKey);

         expect(asByteArray).toEqual(testInfo.publicKey);
       });

    describe('getPublicKeyFromByteArray', () => {
      it('should fail when called with an invalid key', async () => {
        await expectAsync(
            hpkeUtil.getPublicKeyFromByteArray(
                testInfo.curveType, randBytes(testInfo.publicKey.length - 1)))
            .toBeRejectedWithError(SecurityException);
      });
    });

    describe('getPrivateKeyFromByteArray', () => {
      it('should fail when called with an invalid public key', async () => {
        await expectAsync(hpkeUtil.getPrivateKeyFromByteArray({
          curveType: testInfo.curveType,
          publicKey: randBytes(testInfo.publicKey.length - 1),
          privateKey: testInfo.privateKey,
        })).toBeRejectedWithError(SecurityException);
      });

      it('should fail when called with an invalid private key', async () => {
        await expectAsync(hpkeUtil.getPrivateKeyFromByteArray({
          curveType: testInfo.curveType,
          publicKey: testInfo.publicKey,
          privateKey: new Uint8Array(0),
        })).toBeRejectedWithError(DOMException);
      });
    });
  }

  describe('numberToByteArray', () => {
    it('should convert values correctly', async () => {
      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 0, 0))
          .toEqual(new Uint8Array(0));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 1, 0))
          .toEqual(Uint8Array.of(0x00));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 2, 0))
          .toEqual(Uint8Array.of(0x00, 0x00));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 1, 1))
          .toEqual(Uint8Array.of(0x01));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 2, 1))
          .toEqual(Uint8Array.of(0x00, 0x01));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 1, 127))
          .toEqual(Uint8Array.of(0x7F));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 2, 127))
          .toEqual(Uint8Array.of(0x00, 0x7F));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 3, 127))
          .toEqual(Uint8Array.of(0x00, 0x00, 0x7F));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 1, 128))
          .toEqual(Uint8Array.of(0x80));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 2, 128))
          .toEqual(Uint8Array.of(0x00, 0x80));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 3, 128))
          .toEqual(Uint8Array.of(0x00, 0x00, 0x80));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 1, 255))
          .toEqual(Uint8Array.of(0xFF));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 2, 255))
          .toEqual(Uint8Array.of(0x00, 0xFF));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 3, 255))
          .toEqual(Uint8Array.of(0x00, 0x00, 0xFF));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 2, 256))
          .toEqual(Uint8Array.of(0x01, 0x00));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 2, 258))
          .toEqual(Uint8Array.of(0x01, 0x02));

      expect(hpkeUtil.numberToByteArray(/*intendedLength*/ 4, 258))
          .toEqual(Uint8Array.of(0x00, 0x00, 0x01, 0x02));
    });
  });

  describe('bigIntToByteArray', () => {
    it('should convert values correctly', async () => {
      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 0, BigInt(0)))
          .toEqual(new Uint8Array(0));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 1, BigInt(0)))
          .toEqual(Uint8Array.of(0x00));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 2, BigInt(0)))
          .toEqual(Uint8Array.of(0x00, 0x00));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 1, BigInt(1)))
          .toEqual(Uint8Array.of(0x01));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 2, BigInt(1)))
          .toEqual(Uint8Array.of(0x00, 0x01));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 1, BigInt(127)))
          .toEqual(Uint8Array.of(0x7F));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 2, BigInt(127)))
          .toEqual(Uint8Array.of(0x00, 0x7F));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 3, BigInt(127)))
          .toEqual(Uint8Array.of(0x00, 0x00, 0x7F));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 1, BigInt(128)))
          .toEqual(Uint8Array.of(0x80));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 2, BigInt(128)))
          .toEqual(Uint8Array.of(0x00, 0x80));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 3, BigInt(128)))
          .toEqual(Uint8Array.of(0x00, 0x00, 0x80));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 1, BigInt(255)))
          .toEqual(Uint8Array.of(0xFF));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 2, BigInt(255)))
          .toEqual(Uint8Array.of(0x00, 0xFF));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 3, BigInt(255)))
          .toEqual(Uint8Array.of(0x00, 0x00, 0xFF));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 2, BigInt(256)))
          .toEqual(Uint8Array.of(0x01, 0x00));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 2, BigInt(258)))
          .toEqual(Uint8Array.of(0x01, 0x02));

      expect(hpkeUtil.bigIntToByteArray(/*intendedLength*/ 4, BigInt(258)))
          .toEqual(Uint8Array.of(0x00, 0x00, 0x01, 0x02));
    });
  });

  describe('nistHpkeKemToCurve', () => {
    it('should convert values correctly', async () => {
      expect(hpkeUtil.nistHpkeKemToCurve(PbHpkeKem.DHKEM_P256_HKDF_SHA256))
          .toEqual(ellipticCurves.CurveType.P256);

      expect(hpkeUtil.nistHpkeKemToCurve(PbHpkeKem.DHKEM_P521_HKDF_SHA512))
          .toEqual(ellipticCurves.CurveType.P521);
    });

    it('should fail for unknown kem value', async () => {
      try {
        hpkeUtil.nistHpkeKemToCurve(PbHpkeKem.KEM_UNKNOWN);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized NIST HPKE KEM identifier');
      }
    });
  });
});
