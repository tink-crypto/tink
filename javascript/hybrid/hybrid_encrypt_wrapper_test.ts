/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {CryptoFormat} from '../internal/crypto_format';
import * as PrimitiveSet from '../internal/primitive_set';
import {PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as Random from '../subtle/random';
import {assertExists} from '../testing/internal/test_utils';

import {HybridEncryptWrapper} from './hybrid_encrypt_wrapper';
import {HybridEncrypt} from './internal/hybrid_encrypt';

describe('hybrid encrypt wrapper test', function() {
  it('new hybrid encrypt, primitive set without primary', function() {
    const primitiveSet = createDummyPrimitiveSet(/* opt_withPrimary = */ false);
    try {
      new HybridEncryptWrapper().wrap(primitiveSet);
      fail('Should throw an exception.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.primitiveSetWithoutPrimary());
    }
  });

  it('new hybrid encrypt, should work', function() {
    const primitiveSet = createDummyPrimitiveSet();
    const hybridEncrypt = new HybridEncryptWrapper().wrap(primitiveSet);
    expect(hybridEncrypt != null && hybridEncrypt != undefined).toBe(true);
  });

  it('encrypt, should work', async function() {
    const primitiveSet = createDummyPrimitiveSet();
    const hybridEncrypt = new HybridEncryptWrapper().wrap(primitiveSet);

    const plaintext = Random.randBytes(10);

    const ciphertext = await hybridEncrypt.encrypt(plaintext);
    expect(ciphertext != null).toBe(true);

    // Ciphertext should begin with primary key output prefix.
    expect(ciphertext.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE))
        .toEqual(assertExists(primitiveSet.getPrimary()).getIdentifier());
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

  static nullPlaintext(): string {
    return 'SecurityException: Plaintext has to be non-null.';
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
 * Creates a primitive set with 'numberOfPrimitives' primitives. The keys
 * corresponding to the primitives have ids from the set
 * [1, ..., numberOfPrimitives] and the primitive corresponding to key with id
 * 'numberOfPrimitives' is set to be primary whenever opt_withPrimary is set to
 * true (where true is the default value).
 */
function createDummyPrimitiveSet(opt_withPrimary: boolean = true):
    PrimitiveSet.PrimitiveSet<DummyHybridEncrypt> {
  const numberOfPrimitives = 5;
  const primitiveSet =
      new PrimitiveSet.PrimitiveSet<HybridEncrypt>(HybridEncrypt);
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
    const hybridEncrypt = new DummyHybridEncrypt();
    primitiveSet.addPrimitive(hybridEncrypt, key);
  }

  const key = createDummyKeysetKey(
      numberOfPrimitives, PbOutputPrefixType.TINK, /* enabled = */ true);
  const hybridEncrypt = new DummyHybridEncrypt();
  const entry = primitiveSet.addPrimitive(hybridEncrypt, key);
  if (opt_withPrimary) {
    primitiveSet.setPrimary(entry);
  }

  return primitiveSet;
}

/** @final */
class DummyHybridEncrypt extends HybridEncrypt {
  async encrypt(plaintext: Uint8Array, opt_contextInfo: Uint8Array) {
    return plaintext;
  }
}
