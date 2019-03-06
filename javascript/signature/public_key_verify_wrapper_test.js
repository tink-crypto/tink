// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.signature.PublicKeyVerifyWrapperTest');
goog.setTestOnly('tink.signature.PublicKeyVerifyWrapperTest');

const Bytes = goog.require('tink.subtle.Bytes');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeysetKey = goog.require('proto.google.crypto.tink.Keyset.Key');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PublicKeySign = goog.require('tink.PublicKeySign');
const PublicKeySignWrapper = goog.require('tink.signature.PublicKeySignWrapper');
const PublicKeyVerify = goog.require('tink.PublicKeyVerify');
const PublicKeyVerifyWrapper = goog.require('tink.signature.PublicKeyVerifyWrapper');
const Random = goog.require('tink.subtle.Random');
const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  async testNewPublicKeyVerify_nullPrimitiveSet() {
    try {
      new PublicKeyVerifyWrapper().wrap(null);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: Primitive set has to be non-null.', e.toString());
    }
  },

  async testVerify_withNullSignature() {
    const primitiveSets = createDummyPrimitiveSets();
    const primitiveSet = primitiveSets['publicPrimitiveSet'];
    const publicKeyVerify = new PublicKeyVerifyWrapper().wrap(primitiveSet);

    try {
      await publicKeyVerify.verify(null, Random.randBytes(10));
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
  },

  async testVerify_withNullData() {
    const primitiveSets = createDummyPrimitiveSets();
    const primitiveSet = primitiveSets['publicPrimitiveSet'];
    const publicKeyVerify = new PublicKeyVerifyWrapper().wrap(primitiveSet);

    try {
      await publicKeyVerify.verify(Random.randBytes(10), null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: input must be a non null Uint8Array', e.toString());
    }
  },

  async testVerify_shouldWork() {
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
    assertTrue(isValid);
  },

  async testVerify_rawPrimitive() {
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
    assertTrue(isValid);
  },

  async testVerify_withDisabledPrimitive() {
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
    assertFalse(isValid);
  },
});

/**
 * Function for creating keys for testing purposes.
 *
 * @param {number} keyId
 * @param {!PbOutputPrefixType} outputPrefix
 * @param {boolean} enabled
 *
 * @return {!PbKeysetKey}
 */
const createDummyKeysetKey = function(keyId, outputPrefix, enabled) {
  let key = new PbKeysetKey();

  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  key.setOutputPrefixType(outputPrefix);
  key.setKeyId(keyId);

  return key;
};

/**
 * Creates a primitive sets for PublicKeySign and PublicKeyVerify with
 * 'numberOfPrimitives' primitives. The keys corresponding to the primitives
 * have ids from the set [1, ..., numberOfPrimitives] and the primitive
 * corresponding to key with id 'numberOfPrimitives' is set to be primary
 * whenever opt_withPrimary is set to true (where true is the default value).
 *
 * @param {boolean=} opt_withPrimary
 * @return {{publicPrimitiveSet:!PrimitiveSet.PrimitiveSet,
 *     privatePrimitiveSet:!PrimitiveSet.PrimitiveSet}}
 */
const createDummyPrimitiveSets = function(opt_withPrimary = true) {
  const numberOfPrimitives = 5;

  const publicPrimitiveSet = new PrimitiveSet.PrimitiveSet();
  const privatePrimitiveSet = new PrimitiveSet.PrimitiveSet();
  for (let i = 1; i < numberOfPrimitives; i++) {
    let /** @type {!PbOutputPrefixType} */ outputPrefix;
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
};

/**
 * @implements {PublicKeySign}
 * @final
 */
class DummyPublicKeySign {
  /** @param {!Uint8Array} signatureSuffix */
  constructor(signatureSuffix) {
    this.signatureSuffix_ = signatureSuffix;
  }
  /** @override */
  async sign(data) {
    return Bytes.concat(data, this.signatureSuffix_);
  }
}

/**
 * @implements {PublicKeyVerify}
 * @final
 */
class DummyPublicKeyVerify {
  /** @param {!Uint8Array} signatureSuffix */
  constructor(signatureSuffix) {
    this.signatureSuffix_ = signatureSuffix;
  }

  /** @override */
  async verify(signature, data) {
    return Bytes.isEqual(Bytes.concat(data, this.signatureSuffix_), signature);
  }
}
