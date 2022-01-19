/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as PrimitiveSet from '../internal/primitive_set';
import {PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as Bytes from '../subtle/bytes';
import * as Random from '../subtle/random';

import {PublicKeySign} from './internal/public_key_sign';
import {PublicKeyVerify} from './internal/public_key_verify';
import {PublicKeySignWrapper} from './public_key_sign_wrapper';
import {PublicKeyVerifyWrapper} from './public_key_verify_wrapper';

describe('public key verify wrapper test', function() {
  it('verify, with empty signature', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const primitiveSet = primitiveSets['publicPrimitiveSet'];
    const publicKeyVerify = new PublicKeyVerifyWrapper().wrap(primitiveSet);
    expect(
        await publicKeyVerify.verify(new Uint8Array(0), Random.randBytes(10)))
        .toBe(false);
  });

  it('verify, should work', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const data = Random.randBytes(10);
    // As keys are just dummy keys which do not contain key data, the same key
    // is used for both sign and verify.
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.TINK,
        /** enabled = */ true);
    const signatureSuffix = Random.randBytes(10);

    // Get the signature
    const privatePrimitiveSet = primitiveSets['privatePrimitiveSet'];
    const signPrimitive = new DummyPublicKeySign(signatureSuffix);
    const entry = privatePrimitiveSet.addPrimitive(signPrimitive, key);
    // Has to be set to primary as then it is used in signing.
    privatePrimitiveSet.setPrimary(entry);
    const publicKeySign = new PublicKeySignWrapper().wrap(privatePrimitiveSet);
    const signature = await publicKeySign.sign(data);

    // Create a primitive set containing the primitives which can be used for
    // verification. Add also few more primitives with the same key as the
    // primitive set should verify the signature whenever there is at least
    // one primitive which does not fail to verify the signature.
    const publicPrimitiveSet = primitiveSets['publicPrimitiveSet'];
    const verifyPrimitive = new DummyPublicKeyVerify(signatureSuffix);
    publicPrimitiveSet.addPrimitive(
        new DummyPublicKeyVerify(Random.randBytes(5)), key);
    publicPrimitiveSet.addPrimitive(verifyPrimitive, key);
    publicPrimitiveSet.addPrimitive(
        new DummyPublicKeyVerify(Random.randBytes(5)), key);

    // Verify the signature.
    const publicKeyVerify =
        new PublicKeyVerifyWrapper().wrap(publicPrimitiveSet);

    const isValid = await publicKeyVerify.verify(signature, data);
    expect(isValid).toBe(true);
  });

  it('verify, raw primitive', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const data = Random.randBytes(10);
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ true);
    const signatureSuffix = Random.randBytes(10);

    // Get the signature.
    const signPrimitive = new DummyPublicKeySign(signatureSuffix);
    const signature = await signPrimitive.sign(data);

    // Verify the signature.
    const primitiveSet = primitiveSets['publicPrimitiveSet'];
    const verifyPrimitive = new DummyPublicKeyVerify(signatureSuffix);
    primitiveSet.addPrimitive(verifyPrimitive, key);
    const publicKeyVerify = new PublicKeyVerifyWrapper().wrap(primitiveSet);

    const isValid = await publicKeyVerify.verify(signature, data);
    expect(isValid).toBe(true);
  });

  it('verify, with disabled primitive', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const data = Random.randBytes(10);
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ false);
    const signatureSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    const signPrimitive = new DummyPublicKeySign(signatureSuffix);
    const signature = await signPrimitive.sign(data);

    const primitiveSet = primitiveSets['publicPrimitiveSet'];
    const verifyPrimitive = new DummyPublicKeyVerify(signatureSuffix);
    primitiveSet.addPrimitive(verifyPrimitive, key);
    const publicKeyVerify = new PublicKeyVerifyWrapper().wrap(primitiveSet);

    const isValid = await publicKeyVerify.verify(signature, data);
    expect(isValid).toBe(false);
  });
});

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
 * Creates a primitive sets for PublicKeySign and PublicKeyVerify with
 * 'numberOfPrimitives' primitives. The keys corresponding to the primitives
 * have ids from the set [1, ..., numberOfPrimitives] and the primitive
 * corresponding to key with id 'numberOfPrimitives' is set to be primary
 * whenever opt_withPrimary is set to true (where true is the default value).
 */
function createDummyPrimitiveSets(opt_withPrimary: boolean = true): {
  publicPrimitiveSet: PrimitiveSet.PrimitiveSet<DummyPublicKeyVerify>,
  privatePrimitiveSet: PrimitiveSet.PrimitiveSet<DummyPublicKeySign>,
} {
  const numberOfPrimitives = 5;

  const publicPrimitiveSet =
      new PrimitiveSet.PrimitiveSet<DummyPublicKeyVerify>(DummyPublicKeyVerify);
  const privatePrimitiveSet =
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
    const signatureSuffix = new Uint8Array([0, 0, i]);
    const publicKeySign = new DummyPublicKeySign(signatureSuffix);
    privatePrimitiveSet.addPrimitive(publicKeySign, key);
    const publicKeyVerify = new DummyPublicKeyVerify(signatureSuffix);
    publicPrimitiveSet.addPrimitive(publicKeyVerify, key);
  }

  const key = createDummyKeysetKey(
      numberOfPrimitives, PbOutputPrefixType.TINK, /* enabled = */ true);
  const signatureSuffix = new Uint8Array([0, 0, numberOfPrimitives]);
  const publicKeySign = new DummyPublicKeySign(signatureSuffix);
  const signEntry = privatePrimitiveSet.addPrimitive(publicKeySign, key);
  const publicKeyVerify = new DummyPublicKeyVerify(signatureSuffix);
  const verifyEntry = publicPrimitiveSet.addPrimitive(publicKeyVerify, key);
  if (opt_withPrimary) {
    publicPrimitiveSet.setPrimary(verifyEntry);
    privatePrimitiveSet.setPrimary(signEntry);
  }

  return {
    'publicPrimitiveSet': publicPrimitiveSet,
    'privatePrimitiveSet': privatePrimitiveSet
  };
}

/** @final */
class DummyPublicKeySign extends PublicKeySign {
  constructor(private readonly signatureSuffix: Uint8Array) {
    super();
  }

  async sign(data: Uint8Array) {
    return Bytes.concat(data, this.signatureSuffix);
  }
}

/** @final */
class DummyPublicKeyVerify extends PublicKeyVerify {
  constructor(private readonly signatureSuffix: Uint8Array) {
    super();
  }

  async verify(signature: Uint8Array, data: Uint8Array) {
    return Bytes.isEqual(Bytes.concat(data, this.signatureSuffix), signature);
  }
}
