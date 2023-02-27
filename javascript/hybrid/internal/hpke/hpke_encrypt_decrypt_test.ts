/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {SecurityException} from '../../../exception/security_exception';
import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeParams, PbHpkePrivateKey, PbHpkePublicKey} from '../../../internal/proto';
import * as bytes from '../../../subtle/bytes';
import * as random from '../../../subtle/random';

import {HpkeDecrypt} from './hpke_decrypt';
import {HpkeEncrypt} from './hpke_encrypt';

interface TestVector {
  kem: PbHpkeKem;
  kdf: PbHpkeKdf;
  aead: PbHpkeAead;
  recipientPublicKey: Uint8Array;
  recipientPrivateKey: Uint8Array;
}

/**
 * Test vectors as described in @see https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
 */
const TEST_VECTORS: TestVector[] = [
  /** Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM */
  {
    kem: PbHpkeKem.DHKEM_P256_HKDF_SHA256,
    kdf: PbHpkeKdf.HKDF_SHA256,
    aead: PbHpkeAead.AES_128_GCM,
    recipientPublicKey: bytes.fromHex(
        '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0'),
    recipientPrivateKey: bytes.fromHex(
        'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2'),
  },
  /** Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM */
  {
    kem: PbHpkeKem.DHKEM_P521_HKDF_SHA512,
    kdf: PbHpkeKdf.HKDF_SHA512,
    aead: PbHpkeAead.AES_256_GCM,
    recipientPublicKey: bytes.fromHex(
        '0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64'),
    recipientPrivateKey: bytes.fromHex(
        '01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847'),
  }
];

const validPrivateKeyBytes = TEST_VECTORS[0].recipientPrivateKey;
const validPublicKeyBytes = TEST_VECTORS[0].recipientPublicKey;

function getValidParams() {
  return new PbHpkeParams()
      .setKem(TEST_VECTORS[0].kem)
      .setKdf(TEST_VECTORS[0].kdf)
      .setAead(TEST_VECTORS[0].aead);
}

function getPublicKey(params: PbHpkeParams) {
  return new PbHpkePublicKey().setParams(params).setPublicKey(
      validPublicKeyBytes);
}

function getPrivateKey(publicKey: PbHpkePublicKey) {
  return new PbHpkePrivateKey().setPublicKey(publicKey).setPrivateKey(
      validPrivateKeyBytes);
}

describe('HpkeEncryptDecrypt', () => {
  beforeEach(() => {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(() => {
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });
  for (const testInfo of TEST_VECTORS) {
    const hpkeParams = new PbHpkeParams()
                           .setKem(testInfo.kem)
                           .setKdf(testInfo.kdf)
                           .setAead(testInfo.aead);
    const hpkePublicKey = new PbHpkePublicKey()
                              .setParams(hpkeParams)
                              .setPublicKey(testInfo.recipientPublicKey);
    const hpkePrivateKey = new PbHpkePrivateKey()
                               .setPrivateKey(testInfo.recipientPrivateKey)
                               .setPublicKey(hpkePublicKey);
    const input = random.randBytes(200);
    const contextInfo = random.randBytes(110);
    it('should encrypt and decrypt correctly', async () => {
      const hpkeDecrypt = await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
      const hpkeEncrypt = await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
      const ciphertext = await hpkeEncrypt.encrypt(input, contextInfo);
      const plaintext = await hpkeDecrypt.decrypt(ciphertext, contextInfo);

      expect(plaintext).toEqual(input);
    });

    it('should encrypt and decrypt correctly with null context info',
       async () => {
         const emptyContextInfo = new Uint8Array(0);
         const hpkeDecrypt =
             await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
         const hpkeEncrypt = await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
         const ciphertextWithEmptyContext =
             await hpkeEncrypt.encrypt(input, emptyContextInfo);

         expect(await hpkeDecrypt.decrypt(
                    ciphertextWithEmptyContext, emptyContextInfo))
             .toEqual(input);
       });

    it('fails with truncated ciphertext', async () => {
      const hpkeDecrypt = await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
      const hpkeEncrypt = await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
      const ciphertext = await hpkeEncrypt.encrypt(input, contextInfo);
      const truncatedCiphertext = ciphertext.slice(0, 10);
      await expectAsync(hpkeDecrypt.decrypt(truncatedCiphertext, contextInfo))
          .toBeRejectedWithError(SecurityException);
    });

    it('fails with modified ciphertext', async () => {
      const hpkeDecrypt = await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
      const hpkeEncrypt = await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
      const ciphertext = await hpkeEncrypt.encrypt(input, contextInfo);
      const modifiedCiphertext = random.randBytes(ciphertext.length);
      await expectAsync(hpkeDecrypt.decrypt(modifiedCiphertext, contextInfo))
          .toBeRejectedWithError(InvalidArgumentsException);
    });

    it('fails with truncated context info', async () => {
      const hpkeDecrypt = await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
      const hpkeEncrypt = await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
      const ciphertext = await hpkeEncrypt.encrypt(input, contextInfo);
      const truncatedContextInfo = contextInfo.slice(0, 10);
      await expectAsync(hpkeDecrypt.decrypt(ciphertext, truncatedContextInfo))
          .toBeRejectedWithError(SecurityException);
    });

    it('fails with modified context info', async () => {
      const hpkeDecrypt = await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
      const hpkeEncrypt = await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
      const ciphertext = await hpkeEncrypt.encrypt(input, contextInfo);
      const modifiedContextInfo = random.randBytes(contextInfo.length);
      await expectAsync(hpkeDecrypt.decrypt(ciphertext, modifiedContextInfo))
          .toBeRejectedWithError(SecurityException);
    });
  }

  describe('fails to instantiate with', () => {
    it('unknown kem', async () => {
      const unknownKemParams = getValidParams().setKem(PbHpkeKem.KEM_UNKNOWN);
      const hpkePublicKey = getPublicKey(unknownKemParams);
      const hpkePrivateKey = getPrivateKey(hpkePublicKey);
      try {
        await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KEM identifier');
      }
      try {
        await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KEM identifier');
      }
    });

    it('unknown kdf', async () => {
      const unknownKdfParams = getValidParams().setKdf(PbHpkeKdf.KDF_UNKNOWN);
      const hpkePublicKey = getPublicKey(unknownKdfParams);
      const hpkePrivateKey = getPrivateKey(hpkePublicKey);
      try {
        await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KDF identifier');
      }
      try {
        await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KDF identifier');
      }
    });

    it('unknown aead', async () => {
      const unknownAeadParams =
          getValidParams().setAead(PbHpkeAead.AEAD_UNKNOWN);
      const hpkePublicKey = getPublicKey(unknownAeadParams);
      const hpkePrivateKey = getPrivateKey(hpkePublicKey);
      try {
        await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKey);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE AEAD identifier');
      }
      try {
        await HpkeEncrypt.createHpkeEncrypt(hpkePublicKey);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE AEAD identifier');
      }
    });

    it('missing public key', async () => {
      const hpkePrivateKeyMissingPublic =
          new PbHpkePrivateKey().setPrivateKey(validPrivateKeyBytes);
      try {
        await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKeyMissingPublic);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Recipient private key is missing public key field.');
      }
    });

    it('zero length public key', async () => {
      const hpkePublicKeyZeroLength = new PbHpkePublicKey()
                                          .setPublicKey(new Uint8Array(0))
                                          .setParams(getValidParams());
      try {
        await HpkeEncrypt.createHpkeEncrypt(hpkePublicKeyZeroLength);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Recipient public key is empty.');
      }
    });

    it('missing hpke params', async () => {
      const hpkePublicKeyMissingParams =
          new PbHpkePublicKey().setPublicKey(validPublicKeyBytes);
      try {
        await HpkeEncrypt.createHpkeEncrypt(hpkePublicKeyMissingParams);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Public key is missing params field.');
      }
    });

    it('zero length private key', async () => {
      const hpkePrivateKeyZeroLength =
          new PbHpkePrivateKey()
              .setPrivateKey(new Uint8Array(0))
              .setPublicKey(getPublicKey(getValidParams()));
      try {
        await HpkeDecrypt.createHpkeDecrypt(hpkePrivateKeyZeroLength);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Recipient private key is empty.');
      }
    });
  });
});
