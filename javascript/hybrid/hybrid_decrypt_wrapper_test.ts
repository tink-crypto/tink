/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as PrimitiveSet from '../internal/primitive_set';
import {PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as Bytes from '../subtle/bytes';
import * as Random from '../subtle/random';

import {HybridDecryptWrapper} from './hybrid_decrypt_wrapper';
import {HybridEncryptWrapper} from './hybrid_encrypt_wrapper';
import {HybridDecrypt} from './internal/hybrid_decrypt';
import {HybridEncrypt} from './internal/hybrid_encrypt';

describe('hybrid decrypt wrapper test', function() {
  it('decrypt, invalid ciphertext', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);
    // Ciphertext which cannot be decrypted by any primitive in the primitive
    // set.
    const ciphertext = new Uint8Array([9, 8, 7, 6, 5, 4, 3]);

    try {
      await hybridDecrypt.decrypt(ciphertext);
      fail('Should throw an exception');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
  });

  it('decrypt, should work', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    // As keys are just dummy keys which do not contain key data, the same key
    // is used for both encrypt and decrypt.
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.TINK,
        /** enabled = */ true);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Get the ciphertext.
    const encryptPrimitiveSet = primitiveSets['encryptPrimitiveSet'];
    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const entry = encryptPrimitiveSet.addPrimitive(encryptPrimitive, key);
    // Has to be set to primary as then it is used in encryption.
    encryptPrimitiveSet.setPrimary(entry);
    const hybridEncrypt = new HybridEncryptWrapper().wrap(encryptPrimitiveSet);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);

    // Create a primitive set containing the primitive which can be used for
    // encryption. Add also few more primitives with the same key as the
    // primitive set should decrypt the ciphertext whenever there is at least
    // one primitive which does not fail to decrypt the ciphertext.
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(
        new DummyHybridDecrypt(Random.randBytes(5)), key);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    decryptPrimitiveSet.addPrimitive(
        new DummyHybridDecrypt(Random.randBytes(5)), key);

    // Decrypt the ciphertext.
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);
    const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

    // Test that the result is the original plaintext.
    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('decrypt, ciphertext encrypted by raw primitive', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    // As keys are just dummy keys which do not contain key data, the same key
    // is used for both encrypt and decrypt.
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ true);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Get the ciphertext.
    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const ciphertext = await encryptPrimitive.encrypt(plaintext);

    // Decrypt the ciphertext.
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);
    const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

    // Test that the result is the original plaintext.
    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('decrypt, with context info', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    const contextInfo = Random.randBytes(10);
    // As keys are just dummy keys which do not contain key data, the same key
    // is used for both encrypt and decrypt.
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ true);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Get the ciphertext.
    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const ciphertext = await encryptPrimitive.encrypt(plaintext, contextInfo);

    // Get primitive for decryption.
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);

    // Check that contextInfo was passed correctly (decryption without
    // contextInfo argument should not work, but with contextInfo it should work
    // properly).
    try {
      await hybridDecrypt.decrypt(ciphertext);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
    const decryptedCiphertext =
        await hybridDecrypt.decrypt(ciphertext, contextInfo);

    // Test that the result is the original plaintext.
    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('decrypt, with disabled primitive', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ false);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const ciphertext = await encryptPrimitive.encrypt(plaintext);

    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);

    try {
      await hybridDecrypt.decrypt(ciphertext);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
  });

  it('decrypt, with empty ciphertext', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);

    try {
      await hybridDecrypt.decrypt(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
  });
});

/** @final */
class ExceptionText {
  static nullPrimitiveSet(): string {
    return 'SecurityException: Primitive set has to be non-null.';
  }

  static cannotBeDecrypted(): string {
    return 'SecurityException: Decryption failed for the given ciphertext.';
  }

  static nullCiphertext(): string {
    return 'SecurityException: Ciphertext has to be non-null.';
  }
}

/** Function for creating keys for testing purposes. */
function createDummyKeysetKey(
    keyId: number, outputPrefix: PbOutputPrefixType,
    enabled: boolean): PbKeysetKey {
  const key = new PbKeysetKey();

  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  key.setOutputPrefixType(outputPrefix);
  key.setKeyId(keyId);

  return key;
}

/**
 * Creates a primitive sets for HybridEncrypt and HybridDecrypt with
 * 'numberOfPrimitives' primitives. The keys corresponding to the primitives
 * have ids from the set [1, ..., numberOfPrimitives] and the primitive
 * corresponding to key with id 'numberOfPrimitives' is set to be primary
 * whenever opt_withPrimary is set to true (where true is the default value).
 */
function createDummyPrimitiveSets(opt_withPrimary: boolean = true): {
  encryptPrimitiveSet: PrimitiveSet.PrimitiveSet<DummyHybridEncrypt>,
  decryptPrimitiveSet: PrimitiveSet.PrimitiveSet<DummyHybridDecrypt>
} {
  const numberOfPrimitives = 5;

  const encryptPrimitiveSet =
      new PrimitiveSet.PrimitiveSet<DummyHybridEncrypt>(DummyHybridEncrypt);
  const decryptPrimitiveSet =
      new PrimitiveSet.PrimitiveSet<DummyHybridDecrypt>(DummyHybridDecrypt);
  for (let i = 1; i < numberOfPrimitives; i++) {
    let outputPrefix: PbOutputPrefixType;
    switch (i % 3) {
      case 0:
        outputPrefix = PbOutputPrefixType.TINK;
        break;
      case 1:
        outputPrefix = PbOutputPrefixType.LEGACY;
        break;
      default:
        outputPrefix = PbOutputPrefixType.RAW;
    }
    const key =
        createDummyKeysetKey(i, outputPrefix, /* enabled = */ i % 4 < 2);
    const ciphertextSuffix = new Uint8Array([0, 0, i]);
    const hybridEncrypt = new DummyHybridEncrypt(ciphertextSuffix);
    encryptPrimitiveSet.addPrimitive(hybridEncrypt, key);
    const hybridDecrypt = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(hybridDecrypt, key);
  }

  const key = createDummyKeysetKey(
      numberOfPrimitives, PbOutputPrefixType.TINK, /* enabled = */ true);
  const ciphertextSuffix = new Uint8Array([0, 0, numberOfPrimitives]);
  const hybridEncrypt = new DummyHybridEncrypt(ciphertextSuffix);
  const encryptEntry = encryptPrimitiveSet.addPrimitive(hybridEncrypt, key);
  const hybridDecrypt = new DummyHybridDecrypt(ciphertextSuffix);
  const decryptEntry = decryptPrimitiveSet.addPrimitive(hybridDecrypt, key);
  if (opt_withPrimary) {
    encryptPrimitiveSet.setPrimary(encryptEntry);
    decryptPrimitiveSet.setPrimary(decryptEntry);
  }

  return {
    'encryptPrimitiveSet': encryptPrimitiveSet,
    'decryptPrimitiveSet': decryptPrimitiveSet
  };
}

/** @final */
class DummyHybridEncrypt extends HybridEncrypt {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }

  async encrypt(plaintext: Uint8Array, opt_contextInfo?: Uint8Array) {
    const ciphertext = Bytes.concat(plaintext, this.ciphertextSuffix);
    if (opt_contextInfo) {
      return Bytes.concat(ciphertext, opt_contextInfo);
    }
    return ciphertext;
  }
}

/** @final */
class DummyHybridDecrypt extends HybridDecrypt {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }

  async decrypt(ciphertext: Uint8Array, opt_contextInfo?: Uint8Array) {
    if (opt_contextInfo) {
      const infoLength = opt_contextInfo.length;
      const contextInfo =
          ciphertext.slice(ciphertext.length - infoLength, ciphertext.length);
      if ([...contextInfo].toString() !== [...opt_contextInfo].toString()) {
        throw new SecurityException('Context info does not match.');
      }
      ciphertext = ciphertext.slice(0, ciphertext.length - infoLength);
    }
    const plaintext =
        ciphertext.slice(0, ciphertext.length - this.ciphertextSuffix.length);
    const suffix = ciphertext.slice(
        ciphertext.length - this.ciphertextSuffix.length, ciphertext.length);
    if ([...suffix].toString() === [...this.ciphertextSuffix].toString()) {
      return plaintext;
    }
    throw new SecurityException(ExceptionText.cannotBeDecrypted());
  }
}
