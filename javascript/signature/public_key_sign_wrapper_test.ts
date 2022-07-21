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

import {PublicKeySign} from './internal/public_key_sign';
import {PublicKeySignWrapper} from './public_key_sign_wrapper';

describe('public key sign wrapper test', function() {
  it('new public key sign, primitive set without primary', function() {
    const primitiveSet = createDummyPrimitiveSet(/* opt_withPrimary = */ false);
    try {
      new PublicKeySignWrapper().wrap(primitiveSet);
      fail('Should throw an exception.');
    } catch (e: any) {
      expect(e.toString())
          .toBe('SecurityException: Primary has to be non-null.');
    }
  });

  it('new public key sign, should work', function() {
    const primitiveSet = createDummyPrimitiveSet();
    const publicKeySign = new PublicKeySignWrapper().wrap(primitiveSet);
    expect(publicKeySign != null && publicKeySign != undefined).toBe(true);
  });

  it('sign, should work', async function() {
    const primitiveSet = createDummyPrimitiveSet();
    const publicKeySign = new PublicKeySignWrapper().wrap(primitiveSet);

    const data = Random.randBytes(10);

    const signature = await publicKeySign.sign(data);
    expect(signature != null).toBe(true);

    // Signature should begin with primary key output prefix.
    expect(signature.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE))
        .toEqual(assertExists(primitiveSet.getPrimary()).getIdentifier());
  });
});

/**
 * Class holding texts for each type of exception.
 * @final
 */
class ExceptionText {
  static nullPrimitiveSet(): string {
    return 'CustomError: Primitive set has to be non-null.';
  }

  static primitiveSetWithoutPrimary(): string {
    return 'CustomError: Primary has to be non-null.';
  }

  static nullPlaintext(): string {
    return 'CustomError: Plaintext has to be non-null.';
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
    PrimitiveSet.PrimitiveSet<DummyPublicKeySign> {
  const numberOfPrimitives = 5;
  const primitiveSet =
      new PrimitiveSet.PrimitiveSet<DummyPublicKeySign>(DummyPublicKeySign);
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
    const publicKeySign = new DummyPublicKeySign();
    primitiveSet.addPrimitive(publicKeySign, key);
  }

  const key = createDummyKeysetKey(
      numberOfPrimitives, PbOutputPrefixType.TINK, /* enabled = */ true);
  const publicKeySign = new DummyPublicKeySign();
  const entry = primitiveSet.addPrimitive(publicKeySign, key);
  if (opt_withPrimary) {
    primitiveSet.setPrimary(entry);
  }

  return primitiveSet;
}

/** @final */
class DummyPublicKeySign extends PublicKeySign {
  async sign(data: Uint8Array) {
    return data;
  }
}
