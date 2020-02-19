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

goog.module('tink.PrimitiveSetTest');
goog.setTestOnly('tink.PrimitiveSetTest');

const Aead = goog.require('tink.Aead');
const CryptoFormat = goog.require('tink.CryptoFormat');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeysetKey = goog.require('proto.google.crypto.tink.Keyset.Key');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const SecurityException = goog.require('tink.exception.SecurityException');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  /////////////////////////////////////////////////////////////////////////////
  // tests for addPrimitive method
  testAddPrimitiveUnknownCryptoFormat() {
    const primitive = new DummyAead1();
    const key =
        createKey().setOutputPrefixType(PbOutputPrefixType.UNKNOWN_PREFIX);
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

    try {
      primitiveSet.addPrimitive(primitive, key);
    } catch (e) {
      assertEquals(ExceptionText.unknownPrefixType(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testAddPrimitiveNullPrimitive() {
    const primitive = null;
    const key = createKey();
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

    try {
      primitiveSet.addPrimitive(primitive, key);
    } catch (e) {
      assertEquals(ExceptionText.addingNullPrimitive(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testAddPrimitiveMultipleTimesShouldWork() {
    const key = createKey();
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

    for (let i = 0; i < 4; i++) {
      let primitive;
      if (i % 2 === 0) {
        primitive = new DummyAead1();
      } else {
        primitive = new DummyAead2();
      }
      const result = primitiveSet.addPrimitive(primitive, key);

      assertObjectEquals(primitive, result.getPrimitive());
      assertEquals(key.getStatus(), result.getKeyStatus());
      assertEquals(key.getOutputPrefixType(), result.getOutputPrefixType());
      assertObjectEquals(
          CryptoFormat.getOutputPrefix(key), result.getIdentifier());
    }
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitives method
  testGetPrimitivesWhichWereNotAdded() {
    // Fill in the structure with some primitives.
    const numberOfAddedPrimitives = 12;
    const primitiveSet = initPrimitiveSet(numberOfAddedPrimitives);

    const key = createKey(/* opt_keyId = */ numberOfAddedPrimitives + 1);
    const identifier = CryptoFormat.getOutputPrefix(key);
    const result = primitiveSet.getPrimitives(identifier);

    assertObjectEquals([], result);
  },

  testGetPrimitivesDifferentIdentifiers() {
    // Fill in the structure with some primitives.
    const n = 100;
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

    let added = [];
    for (let id = 0; id < n; id++) {
      const legacyKeyType = ((id % 2) < 1);
      const enabledKey = ((id % 4) < 2);
      const key = createKey(id, legacyKeyType, enabledKey);

      let primitive;
      if  ((id % 8) < 4) {
        primitive = new DummyAead1();
      } else {
        primitive = new DummyAead2();
      }

      const res = primitiveSet.addPrimitive(primitive, key);
      added.push({key: key, entry: res});
    }

    // Test that getPrimitives return correct value for them.
    const addedLength = added.length;
    for (let i = 0; i < addedLength; i++) {
      const identifier = CryptoFormat.getOutputPrefix(added[i].key);
      // Should return a set containing only one primitive as each added
      // primitive has different identifier.
      const expectedResult = [added[i].entry];
      const result = primitiveSet.getPrimitives(identifier);

      assertObjectEquals(expectedResult, result);
    }
  },

  testGetPrimitivesSameIdentifiers() {
    // Fill in the structure with some primitives.
    const numberOfAddedPrimitives = 50;
    const primitiveSet = initPrimitiveSet(numberOfAddedPrimitives);

    // Add a group of primitives with same identifier.
    const n = 12;
    const keyId = 0xABCDEF98;
    const legacyKeyType = false;

    let expectedResult = [];
    for (let i = 0; i < n; i++) {
      const enabledKey = ((i % 2) < 1);
      const key = createKey(keyId, legacyKeyType, enabledKey);

      let primitive;
      if  ((i % 4) < 2) {
        primitive = new DummyAead1();
      } else {
        primitive = new DummyAead2();
      }

      const res = primitiveSet.addPrimitive(primitive, key);
      expectedResult.push(res);
    }

    const identifier =
        CryptoFormat.getOutputPrefix(createKey(keyId, legacyKeyType));
    const result = primitiveSet.getPrimitives(identifier);

    assertObjectEquals(expectedResult, result);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getRawPrimitives method
  testGetRawPrimitives() {
    const numberOfAddedPrimitives = 20;
    const primitiveSet = initPrimitiveSet(numberOfAddedPrimitives);

    // No RAW primitives were added.
    let expectedResult = [];
    let result = primitiveSet.getRawPrimitives();
    assertObjectEquals(expectedResult, result);

    // Add RAW primitives and check the result again after each adding.
    let key = createKey().setOutputPrefixType(PbOutputPrefixType.RAW);

    let addResult = primitiveSet.addPrimitive(new DummyAead1(), key);
    expectedResult.push(addResult);
    result = primitiveSet.getRawPrimitives();
    assertObjectEquals(expectedResult, result);

    key.setStatus(PbKeyStatusType.DISABLED);
    addResult = primitiveSet.addPrimitive(new DummyAead2(), key);
    expectedResult.push(addResult);
    result = primitiveSet.getRawPrimitives();
    assertObjectEquals(expectedResult, result);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for setPrimary and getPrimary methods
  testSetPrimaryToNonholdedEntry() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);
    const entry = new PrimitiveSet.Entry(
        new DummyAead1(), new Uint8Array(10), PbKeyStatusType.ENABLED,
        PbOutputPrefixType.TINK);

    try {
      primitiveSet.setPrimary(entry);
    } catch (e) {
      assertEquals(ExceptionText.setPrimaryToMissingEntry(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testSetPrimaryToEntryWithDisabledKeyStatus() {
    const key = createKey(/* opt_keyId = */ 0x12345678,
        /* opt_legacy = */ false, /* opt_enabled = */ false);
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

    const primary = primitiveSet.addPrimitive(new DummyAead1(), key);

    try {
      primitiveSet.setPrimary(primary);
    } catch (e) {
      assertEquals(ExceptionText.setPrimaryToDisabled(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testSetAndGetPrimary() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);
    assertEquals(null, primitiveSet.getPrimary());

    const key1 = createKey(/* opt_keyId = */ 0xBBBCCC);

    const result = primitiveSet.addPrimitive(new DummyAead1(), key1);
    // Check that primary remains unset, set it to newly added and verify that
    // it was set.
    assertEquals(null, primitiveSet.getPrimary());
    primitiveSet.setPrimary(result);
    assertObjectEquals(result, primitiveSet.getPrimary());

    const key2 = createKey(/* opt_keyId = */ 0xAAABBB);
    // Add new primitive, check that it does not change primary.
    const result2 = primitiveSet.addPrimitive(new DummyAead2(), key2);
    assertObjectEquals(result, primitiveSet.getPrimary());

    // Change the primary and verify the change.
    primitiveSet.setPrimary(result2);
    assertObjectEquals(result2, primitiveSet.getPrimary());
  },

  testSetPrimary_rawPrimitives() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);
    for (let i = 0; i < 3; i++) {
      const key = createKey(i).setOutputPrefixType(PbOutputPrefixType.RAW);
      primitiveSet.addPrimitive(new DummyAead1(), key);
    }
    const primaryKey =
        createKey(255).setOutputPrefixType(PbOutputPrefixType.RAW);
    const primaryEntry =
        primitiveSet.addPrimitive(new DummyAead1(), primaryKey);
    primitiveSet.setPrimary(primaryEntry);
  },

  testGetPrimaryType() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);
    assertObjectEquals(Aead, primitiveSet.getPrimitiveType());
  },

});

// Helper classes and functions used for testing purposes.
class ExceptionText {
  /** @return {string} */
  static unknownPrefixType() {
    return 'CustomError: Unsupported key prefix type.';
  }

  /** @return {string} */
  static addingNullPrimitive() {
    return 'CustomError: Primitive has to be non null.';
  }

  /** @return {string} */
  static addingNullKey() {
    return 'CustomError: Key has to be non null.';
  }

  /** @return {string} */
  static setPrimaryToNull() {
    return 'CustomError: Primary cannot be set to null.';
  }

  /** @return {string} */
  static setPrimaryToMissingEntry() {
    return 'CustomError: Primary cannot be set to an entry which is ' +
        'not held by this primitive set.';
  }

  /** @return {string} */
  static setPrimaryToDisabled() {
    return 'CustomError: Primary has to be enabled.';
  }
}

/**
 * @implements {Aead}
 * @final
 */
class DummyAead1 {
  constructor() {}

  /** @override */
  encrypt(plaintext, aad) {
    throw new SecurityException(
        'Not implemented, intentended just for testing.');
  }

  /** @override */
  decrypt(ciphertext, aad) {
    throw new SecurityException(
        'Not implemented, intentended just for testing.');
  }
}

/**
 * @implements {Aead}
 * @final
 */
class DummyAead2 {
  constructor() {}

  /** @override */
  encrypt(plaintext, aad) {
    throw new SecurityException(
        'Not implemented, intentended just for testing.');
  }

  /** @override */
  decrypt(ciphertext, aad) {
    throw new SecurityException(
        'Not implemented, intentended just for testing.');
  }
}

/**
 * Function for creating primitive sets for testing purposes.
 * Returns a primitive set containing n values with keyIds from {0, .. , n-1}.
 * There are different combinations of
 *    primitive types ({DummyAead1, DummyAead2}),
 *    key status (enabled, disabled),
 *    and key types (legacy, tink).
 *
 * @param {number} n
 * @return {!PrimitiveSet.PrimitiveSet}
 */
const initPrimitiveSet = function(n) {
  let primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

  // Set primary.
  const primaryKey = createKey(/* opt_id = */ 0, /* opt_legacy = */ false,
      /* opt_enabled = */ true);
  const primary = primitiveSet.addPrimitive(new DummyAead1(), primaryKey);
  primitiveSet.setPrimary(primary);

  // Add n-1 other keys to primitive set.
  for (let id = 1; id < n; id++) {
    const legacyKeyType = ((id % 2) < 1);
    const enabledKey = ((id % 4) < 2);
    const key = createKey(id, legacyKeyType, enabledKey);

    let primitive;
    if ((id % 8) < 4) {
      primitive = new DummyAead1();
    } else {
      primitive = new DummyAead2();
    }

    primitiveSet.addPrimitive(primitive, key);
  }

  return primitiveSet;
};

/**
 * Function for creating keys for testing purposes.
 * If doesn't set otherwise it generates a key with id 0x12345678, which is
 * ENABLED and with prefix type TINK.
 *
 * @param {number=} opt_keyId
 * @param {boolean=} opt_legacy
 * @param {boolean=} opt_enabled
 *
 * @return{!PbKeysetKey}
 */
const createKey = function(opt_keyId = 0x12345678, opt_legacy = false,
    opt_enabled = true) {
  let key = new PbKeysetKey();

  if (opt_enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  if (opt_legacy) {
    key.setOutputPrefixType(PbOutputPrefixType.LEGACY);
  } else {
    key.setOutputPrefixType(PbOutputPrefixType.TINK);
  }

  key.setKeyId(opt_keyId);

  return key;
};
