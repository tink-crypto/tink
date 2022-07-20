/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {CryptoFormat} from '../internal/crypto_format';
import * as PrimitiveSet from '../internal/primitive_set';
import {PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as Bytes from '../subtle/bytes';
import {assertExists} from '../testing/internal/test_utils';

import {AeadWrapper} from './aead_wrapper';
import {Aead} from './internal/aead';

describe('aead wrapper test', function() {
  it('new aead primitive set without primary', async function() {
    const primitiveSet = createPrimitiveSet(/* opt_withPrimary = */ false);
    try {
      new AeadWrapper().wrap(primitiveSet);
    // This is an intentionally unsafe partial mock
    // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.primitiveSetWithoutPrimary());
      return;
    }
    fail('Should throw an exception.');
  });

  it('new aead primitive should work', async function() {
    const primitiveSet = createPrimitiveSet();
    const aead = new AeadWrapper().wrap(primitiveSet);
    expect(aead != null && aead != undefined).toBe(true);
  });

  it('encrypt', async function() {
    const primitiveSet = createPrimitiveSet();
    const aead = new AeadWrapper().wrap(primitiveSet);

    const plaintext = new Uint8Array([0, 1, 2, 3]);

    const ciphertext = await aead.encrypt(plaintext);
    expect(ciphertext != null).toBe(true);

    // Ciphertext should begin with primary key output prefix.
    expect(ciphertext.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE))
        .toEqual(assertExists(primitiveSet.getPrimary()).getIdentifier());
  });

  it('decrypt bad ciphertext', async function() {
    const primitiveSet = createPrimitiveSet();
    const aead = new AeadWrapper().wrap(primitiveSet);

    const ciphertext = new Uint8Array([9, 8, 7, 6, 5, 4, 3]);

    try {
      await aead.decrypt(ciphertext);
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
      return;
    }
    fail('Should throw an exception');
  });

  it('decrypt with ciphertext encrypted by primary key', async function() {
    const primitiveSet = createPrimitiveSet();
    const aead = new AeadWrapper().wrap(primitiveSet);

    const plaintext = new Uint8Array([12, 51, 45, 200, 120, 111]);

    const ciphertext = await aead.encrypt(plaintext);
    const decryptResult = await aead.decrypt(ciphertext);

    expect(decryptResult).toEqual(plaintext);
  });

  it('decrypt ciphertext encrypted by non primary key', async function() {
    const primitiveSet = createPrimitiveSet();
    const aead = new AeadWrapper().wrap(primitiveSet);

    // Encrypt the plaintext with primary.
    const plaintext = new Uint8Array([0xAA, 0xBB, 0xAB, 0xBA, 0xFF]);
    const ciphertext = await aead.encrypt(plaintext);

    // Add a new primary to primitive set and make new AeadSetWrapper with the
    // updated primitive set.
    const keyId = 0xFFFFFFFF;
    const key =
        createKey(keyId, PbOutputPrefixType.LEGACY, /* enabled = */ true);
    const entry =
        primitiveSet.addPrimitive(new DummyAead(new Uint8Array([0xFF])), key);
    primitiveSet.setPrimary(entry);
    const aead2 = new AeadWrapper().wrap(primitiveSet);

    // Check that the ciphertext can be decrypted by the setWrapper with new
    // primary and that the decryption corresponds to the plaintext.
    const decryptResult = await aead2.decrypt(ciphertext);

    expect(decryptResult).toEqual(plaintext);
  });

  it('decrypt ciphertext raw primitive', async function() {
    const primitiveSet = createPrimitiveSet();
    // Create a RAW primitive and add it to primitiveSet.
    const keyId = 0xFFFFFFFF;
    const rawKey =
        createKey(keyId, PbOutputPrefixType.RAW, /* enabled = */ true);
    const rawKeyAead = new DummyAead(new Uint8Array([0xFF]));
    primitiveSet.addPrimitive(rawKeyAead, rawKey);

    // Encrypt the plaintext by aead corresponding to the rawKey.
    const plaintext = new Uint8Array([0x11, 0x15, 0xAA, 0x54]);
    const ciphertext = await rawKeyAead.encrypt(plaintext);

    // Create aead which should be able to decrypt the ciphertext.
    const aead = new AeadWrapper().wrap(primitiveSet);

    // Try to decrypt the ciphertext by aead and check that the result
    // corresponds to the plaintext.
    const decryptResult = await aead.decrypt(ciphertext);
    expect(decryptResult).toEqual(plaintext);
  });

  it('decrypt ciphertext disabled primitive', async function() {
    const primitiveSet = createPrimitiveSet();

    // Create a primitive with disabled key and add it to primitiveSet.
    const keyId = 0xFFFFFFFF;
    const key = createKey(keyId, PbOutputPrefixType.RAW, /* enabled = */ false);
    const disabledKeyAead = new DummyAead(new Uint8Array([0xFF]));
    primitiveSet.addPrimitive(disabledKeyAead, key);

    // Encrypt the plaintext by a primitive with disabled key.
    const plaintext = new Uint8Array([0, 1, 2, 3]);
    const ciphertext = await disabledKeyAead.encrypt(plaintext);

    // Create aead containing the primitive with disabled key.
    const aead = new AeadWrapper().wrap(primitiveSet);

    // Check that the ciphertext cannot be decrypted as disabled keys cannot be
    // used to neither encryption nor decryption.
    try {
      await aead.decrypt(ciphertext);
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
      return;
    }
    fail('An exception should be thrown.');
  });

  it('encrypt decrypt,  associated data should be passed', async function() {
    const primitiveSet = createPrimitiveSet();
    const aead = new AeadWrapper().wrap(primitiveSet);
    const plaintext = new Uint8Array([0, 1, 2, 3, 4, 5, 6]);
    const aad = new Uint8Array([8, 9, 10, 11, 12]);

    // Encrypt the plaintext with aad. The ciphertext should end with aad if
    // it was passed correctly.
    const ciphertext = await aead.encrypt(plaintext, aad);
    const ciphertextAad =
        ciphertext.slice(ciphertext.length - aad.length, ciphertext.length);
    expect(ciphertextAad).toEqual(aad);

    // Decrypt the ciphertext with aad. It is possible only if aad was passed
    // correctly.
    const decryptedCiphertext = await aead.decrypt(ciphertext, aad);
    expect(decryptedCiphertext).toEqual(plaintext);
  });
});

/**
 * Class holding texts for each type of exception.
 * @final
 */
class ExceptionText {
  static nullPrimitiveSet(): string {
    return 'SecurityException: Primitive set has to be non-null.';
  }

  static primitiveSetWithoutPrimary(): string {
    return 'SecurityException: Primary has to be non-null.';
  }

  static cannotBeDecrypted(): string {
    return 'SecurityException: Decryption failed for the given ciphertext.';
  }
}

/** Function for creating keys for testing purposes. */
function createKey(
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
 * Creates a primitive set with 'numberOfPrimitives' primitives. The keys
 * corresponding to the primitives have ids from the set
 * [1, ..., numberOfPrimitives] and the primitive corresponding to key with id
 * 'numberOfPrimitives' is set to be primary whenever opt_withPrimary is set to
 * true (where true is the default value).
 */
function createPrimitiveSet(opt_withPrimary: boolean = true):
    PrimitiveSet.PrimitiveSet<Aead> {
  const numberOfPrimitives = 5;

  const primitiveSet = new PrimitiveSet.PrimitiveSet<DummyAead>(DummyAead);
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
    const key = createKey(i, outputPrefix, /* enabled = */ i % 4 < 2);
    primitiveSet.addPrimitive(new DummyAead(new Uint8Array([i])), key);
  }

  const key = createKey(
      numberOfPrimitives, PbOutputPrefixType.TINK, /* enabled = */ true);
  const aead = new DummyAead(new Uint8Array([numberOfPrimitives]));
  const entry = primitiveSet.addPrimitive(aead, key);
  if (opt_withPrimary) {
    primitiveSet.setPrimary(entry);
  }

  return primitiveSet;
}

/** @final */
class DummyAead extends Aead {
  constructor(private readonly primitiveIdentifier: Uint8Array) {
    super();
  }

  /** @override*/
  async encrypt(plaintext: Uint8Array, opt_associatedData?: Uint8Array) {
    const result = Bytes.concat(plaintext, this.primitiveIdentifier);
    if (opt_associatedData) {
      return Bytes.concat(result, opt_associatedData);
    }
    return result;
  }

  /** @override*/
  async decrypt(ciphertext: Uint8Array, opt_associatedData?: Uint8Array) {
    if (opt_associatedData) {
      const aad = ciphertext.subarray(
          ciphertext.length - opt_associatedData.length, ciphertext.length);

      if ([...aad].toString() != [...opt_associatedData].toString()) {
        throw new SecurityException(ExceptionText.cannotBeDecrypted());
      }
      ciphertext = ciphertext.subarray(0, ciphertext.length - aad.length);
    }

    const primitiveIdentifier = ciphertext.subarray(
        ciphertext.length - this.primitiveIdentifier.length, ciphertext.length);
    if ([...primitiveIdentifier].toString() !=
        [...this.primitiveIdentifier].toString()) {
      throw new SecurityException(ExceptionText.cannotBeDecrypted());
    }

    return ciphertext.subarray(
        0, ciphertext.length - this.primitiveIdentifier.length);
  }
}
