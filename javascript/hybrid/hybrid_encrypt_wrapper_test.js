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

goog.module('tink.hybrid.HybridEncryptWrapperTest');
goog.setTestOnly('tink.hybrid.HybridEncryptWrapperTest');

const CryptoFormat = goog.require('tink.CryptoFormat');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const HybridEncryptWrapper = goog.require('tink.hybrid.HybridEncryptWrapper');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeysetKey = goog.require('proto.google.crypto.tink.Keyset.Key');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const Random = goog.require('tink.subtle.Random');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testNewHybridEncrypt_nullPrimitiveSet() {
    try {
      new HybridEncryptWrapper().wrap(null);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(ExceptionText.nullPrimitiveSet(), e.toString());
    }
  },

  testNewHybridEncrypt_primitiveSetWithoutPrimary() {
    const primitiveSet = createDummyPrimitiveSet(/* opt_withPrimary = */ false);
    try {
      new HybridEncryptWrapper().wrap(primitiveSet);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(ExceptionText.primitiveSetWithoutPrimary(), e.toString());
    }
  },

  testNewHybridEncrypt_shouldWork() {
    const primitiveSet = createDummyPrimitiveSet();
    const hybridEncrypt = new HybridEncryptWrapper().wrap(primitiveSet);
    assertTrue(hybridEncrypt != null && hybridEncrypt != undefined);
  },

  async testEncrypt_nullPlaintext() {
    const primitiveSet = createDummyPrimitiveSet();
    const hybridEncrypt = new HybridEncryptWrapper().wrap(primitiveSet);

    try {
      await hybridEncrypt.encrypt(null);
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(ExceptionText.nullPlaintext(), e.toString());
    }
  },

  async testEncrypt_shouldWork() {
    const primitiveSet = createDummyPrimitiveSet();
    const hybridEncrypt = new HybridEncryptWrapper().wrap(primitiveSet);

    const plaintext = Random.randBytes(10);

    const ciphertext = await hybridEncrypt.encrypt(plaintext);
    assertTrue(ciphertext != null);

    // Ciphertext should begin with primary key output prefix.
    assertObjectEquals(
        primitiveSet.getPrimary().getIdentifier(),
        ciphertext.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE));
  },
});

/**
 * Class holding texts for each type of exception.
 * @final
 */
class ExceptionText {
  /** @return {string} */
  static nullPrimitiveSet() {
    return 'CustomError: Primitive set has to be non-null.';
  }
  /** @return {string} */
  static primitiveSetWithoutPrimary() {
    return 'CustomError: Primary has to be non-null.';
  }
  /** @return {string} */
  static nullPlaintext() {
    return 'CustomError: Plaintext has to be non-null.';
  }
}

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
 * Creates a primitive set with 'numberOfPrimitives' primitives. The keys
 * corresponding to the primitives have ids from the set
 * [1, ..., numberOfPrimitives] and the primitive corresponding to key with id
 * 'numberOfPrimitives' is set to be primary whenever opt_withPrimary is set to
 * true (where true is the default value).
 *
 * @param {boolean=} opt_withPrimary (default: true)
 * @return {!PrimitiveSet.PrimitiveSet}
 */
const createDummyPrimitiveSet = function(opt_withPrimary = true) {
  const numberOfPrimitives = 5;

  const primitiveSet = new PrimitiveSet.PrimitiveSet();
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
};

/**
 * @implements {HybridEncrypt}
 * @final
 */
class DummyHybridEncrypt {
  /** @override */
  async encrypt(plaintext, opt_contextInfo) {
    return plaintext;
  }
}
