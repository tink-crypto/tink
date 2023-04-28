/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {CryptoFormat} from '../internal/crypto_format';
import * as PrimitiveSet from '../internal/primitive_set';
import {PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as bytes from '../subtle/bytes';
import * as random from '../subtle/random';
import {assertExists} from '../testing/internal/test_utils';

import {Mac} from './internal/mac';
import {MacWrapper} from './mac_wrapper';

describe('mac wrapper test', () => {
  it('new mac primitive set without primary', () => {
    const primitiveSet = createPrimitiveSet(5, /* optWithPrimary = */ false);
    try {
      new MacWrapper().wrap(primitiveSet);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Primary has to be non-null.');
    }
  });

  it('new mac primitive should work', () => {
    const primitiveSet = createPrimitiveSet(5);
    const mac = new MacWrapper().wrap(primitiveSet);
    expect(mac != null && mac !== undefined).toBe(true);
  });

  it('computeMac', async () => {
    const primitiveSet = createPrimitiveSet();
    const mac = new MacWrapper().wrap(primitiveSet);

    const data = new Uint8Array([0, 1, 2, 3]);

    const tag = await mac.computeMac(data);
    expect(tag != null).toBe(true);

    // Tag should begin with the primary key identifier.
    expect(tag.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE))
        .toEqual(assertExists(primitiveSet.getPrimary()).getIdentifier());
  });

  it('verify empty tag should fail', async () => {
    const primitiveSet = createPrimitiveSet();
    const mac = new MacWrapper().wrap(primitiveSet);

    expect(
        await mac.verifyMac(
            /* tag = */ new Uint8Array(0), /* data = */ random.randBytes(10)))
        .toBe(false);
  });

  it('verify tag should work', async () => {
    const primitiveSet = createPrimitiveSet();
    const mac = new MacWrapper().wrap(primitiveSet);

    const data = random.randBytes(10);
    const tag = await mac.computeMac(data);
    const isValid = await mac.verifyMac(tag, data);

    expect(isValid).toBe(true);
  });

  it('verify bad tag should fail', async () => {
    const primitiveSet = createPrimitiveSet();
    const mac = new MacWrapper().wrap(primitiveSet);

    const data = random.randBytes(10);
    const tag = await mac.computeMac(data);
    const modifiedTag = bytes.concat(new Uint8Array([1]), tag);
    const isValid = await mac.verifyMac(modifiedTag, data);

    expect(isValid).toBe(false);
  });

  it('verify tag computed with non primary key', async () => {
    const primitiveSet = createPrimitiveSet();
    const mac = new MacWrapper().wrap(primitiveSet);

    const data = random.randBytes(10);
    const tag = await mac.computeMac(data);

    // Add a new primary to primitive set.
    const keyId = 0xFFFFFFFF;
    const newKey =
        createKey(keyId, PbOutputPrefixType.LEGACY, /* enabled = */ true);
    const entry =
        primitiveSet.addPrimitive(new FakeMac(new Uint8Array([0xFF])), newKey);
    primitiveSet.setPrimary(entry);
    const mac2 = new MacWrapper().wrap(primitiveSet);

    // Check that the tag can be successfully verified by the MacWrapper with
    // the new primary.
    const isValid = await mac2.verifyMac(tag, data);

    expect(isValid).toBe(true);
  });
});

it('verify tag raw primitive', async () => {
  const primitiveSet = createPrimitiveSet();
  // Create a RAW primitive and add it to primitiveSet.
  const keyId = 0xFFFFFFFF;
  const rawKey = createKey(keyId, PbOutputPrefixType.RAW, /* enabled = */ true);
  const rawKeyMac = new FakeMac(new Uint8Array([0xFF]));
  primitiveSet.addPrimitive(rawKeyMac, rawKey);

  // Compute the mac from the rawKey.
  const data = random.randBytes(10);
  const tag = await rawKeyMac.computeMac(data);

  // Create mac which should be able to verify the tag.
  const mac = new MacWrapper().wrap(primitiveSet);

  // Try to verify the tag and checks that it is valid.
  const isValid = await mac.verifyMac(tag, data);
  expect(isValid).toBe(true);
});

it('verify tag disabled primitive', async () => {
  const primitiveSet = createPrimitiveSet();

  // Create a primitive with disabled key and add it to primitiveSet.
  const keyId = 0xFFFFFFFF;
  const key = createKey(keyId, PbOutputPrefixType.RAW, /* enabled = */ false);
  const disabledKeyMac = new FakeMac(new Uint8Array([0xFF]));
  primitiveSet.addPrimitive(disabledKeyMac, key);

  // Compute mac by a primitive with disabled key.
  const data = random.randBytes(10);
  const tag = await disabledKeyMac.computeMac(data);

  // Create mac containing the primitive with disabled key.
  const mac = new MacWrapper().wrap(primitiveSet);

  // Check that the tag is not valid for disabled keys.
  const isValid = await mac.verifyMac(tag, data);
  expect(isValid).toBe(false);
});

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

  key.setOutputPrefixType(outputPrefix).setKeyId(keyId);

  return key;
}

/**
 * Creates a primitive set with 'numberOfPrimitives' primitives. The keys
 * corresponding to the primitives have ids from the set
 * [1, ..., numberOfPrimitives] and the primitive corresponding to key with id
 * 'numberOfPrimitives' is set to be primary whenever optWithPrimary is set to
 * true (where true is the default value).
 */
function createPrimitiveSet(numberOfPrimitives = 5, optWithPrimary = true):
    PrimitiveSet.PrimitiveSet<Mac> {
  const primitiveSet = new PrimitiveSet.PrimitiveSet<FakeMac>(FakeMac);
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
    primitiveSet.addPrimitive(new FakeMac(new Uint8Array([i])), key);
  }

  const key = createKey(
      numberOfPrimitives, PbOutputPrefixType.TINK, /* enabled = */ true);
  const mac = new FakeMac(new Uint8Array([numberOfPrimitives]));
  const entry = primitiveSet.addPrimitive(mac, key);
  if (optWithPrimary) {
    primitiveSet.setPrimary(entry);
  }

  return primitiveSet;
}

/** @final */
class FakeMac extends Mac {
  constructor(private readonly primitiveIdentifier: Uint8Array) {
    super();
  }

  /** @override */
  async computeMac(data: Uint8Array): Promise<Uint8Array> {
    return bytes.concat(data, this.primitiveIdentifier);
  }

  /** @override */
  async verifyMac(tag: Uint8Array, data: Uint8Array): Promise<boolean> {
    return bytes.isEqual(bytes.concat(data, this.primitiveIdentifier), tag);
  }
}
