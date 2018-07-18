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
  async testAddPrimitiveUnknownCryptoFormat() {
    const primitive = new DummyAead1();
    const key = createKey();
    key.setOutputPrefixType(PbOutputPrefixType.UNKNOWN_PREFIX);
    const primitiveSet = new PrimitiveSet.PrimitiveSet();

    try {
      await primitiveSet.addPrimitive(primitive, key);
    } catch (e) {
      assertEquals(ExceptionText.unknownPrefixType(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddPrimitiveNullPrimitive() {
    const primitive = null;
    const key = createKey();
    const primitiveSet = new PrimitiveSet.PrimitiveSet();

    try {
      await primitiveSet.addPrimitive(primitive, key);
    } catch (e) {
      assertEquals(ExceptionText.addingNullPrimitive(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddPrimitiveNullKey() {
    const primitive = new DummyAead1();
    const key = null;
    const primitiveSet = new PrimitiveSet.PrimitiveSet();

    try {
      await primitiveSet.addPrimitive(primitive, key);
    } catch (e) {
      assertEquals(ExceptionText.addingNullKey(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddPrimitiveMultipleTimesShouldWork() {
    const key = createKey();
    const primitiveSet = new PrimitiveSet.PrimitiveSet();

    for (let i = 0; i < 4; i++) {
      let primitive;
      if (i % 2 === 0) {
        primitive = new DummyAead1();
      } else {
        primitive = new DummyAead2();
      }
      const result = await primitiveSet.addPrimitive(primitive, key);

      assertObjectEquals(primitive, result.getPrimitive());
      assertEquals(key.getStatus(), result.getKeyStatus());
      assertEquals(key.getOutputPrefixType(), result.getOutputPrefixType());
      assertObjectEquals(
          CryptoFormat.getOutputPrefix(key), result.getIdentifier());
    }
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitives method
  async testGetPrimitivesWhichWereNotAdded() {
    // Fill in the structure with some primitives.
    const numberOfAddedPrimitives = 12;
    const primitiveSet = await initPrimitiveSet(numberOfAddedPrimitives);

    const key = createKey(/* opt_keyId = */ numberOfAddedPrimitives + 1);
    const identifier = CryptoFormat.getOutputPrefix(key);
    const result = await primitiveSet.getPrimitives(identifier);

    assertObjectEquals([], result);
  },

  async testGetPrimitivesDifferentIdentifiers() {
    // Fill in the structure with some primitives.
    const n = 100;
    const primitiveSet = new PrimitiveSet.PrimitiveSet();

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

      const res = await primitiveSet.addPrimitive(primitive, key);
      added.push({key: key, entry: res});
    }

    // Test that getPrimitives return correct value for them.
    const addedLength = added.length;
    for (let i = 0; i < addedLength; i++) {
      const identifier = CryptoFormat.getOutputPrefix(added[i].key);
      // Should return a set containing only one primitive as each added
      // primitive has different identifier.
      const expectedResult = [added[i].entry];
      const result = await primitiveSet.getPrimitives(identifier);

      assertObjectEquals(expectedResult, result);
    }
  },

  async testGetPrimitivesSameIdentifiers() {
    // Fill in the structure with some primitives.
    const numberOfAddedPrimitives = 50;
    const primitiveSet = await initPrimitiveSet(numberOfAddedPrimitives);

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

      const res = await primitiveSet.addPrimitive(primitive, key);
      expectedResult.push(res);
    }

    const identifier =
        CryptoFormat.getOutputPrefix(createKey(keyId, legacyKeyType));
    const result = await primitiveSet.getPrimitives(identifier);

    assertObjectEquals(expectedResult, result);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getRawPrimitives method
  async testGetRawPrimitives() {
    const numberOfAddedPrimitives = 20;
    const primitiveSet = await initPrimitiveSet(numberOfAddedPrimitives);

    // No RAW primitives were added.
    let expectedResult = [];
    let result = await primitiveSet.getRawPrimitives();
    assertObjectEquals(expectedResult, result);

    // Add RAW primitives and check the result again after each adding.
    let key = createKey();
    key.setOutputPrefixType(PbOutputPrefixType.RAW);

    let addResult = await primitiveSet.addPrimitive(new DummyAead1(), key);
    expectedResult.push(addResult);
    result = await primitiveSet.getRawPrimitives();
    assertObjectEquals(expectedResult, result);

    key.setStatus(PbKeyStatusType.DISABLED);
    addResult = await primitiveSet.addPrimitive(new DummyAead2(), key);
    expectedResult.push(addResult);
    result = await primitiveSet.getRawPrimitives();
    assertObjectEquals(expectedResult, result);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for setPrimary and getPrimary methods
  async testSetPrimaryToNull() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    try {
      await primitiveSet.setPrimary(null);
    } catch (e) {
      assertEquals(ExceptionText.setPrimaryToNull(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testSetPrimaryToNonholdedEntry() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    const entry = new PrimitiveSet.Entry(
        new DummyAead1(), new Uint8Array(10), PbKeyStatusType.ENABLED,
        PbOutputPrefixType.TINK);

    try {
      await primitiveSet.setPrimary(entry);
    } catch (e) {
      assertEquals(ExceptionText.setPrimaryToMissingEntry(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testSetPrimaryToEntryWithCollidingIdentifier() {
    const key = createKey();
    const primitiveSet = new PrimitiveSet.PrimitiveSet();

    for (let i = 0; i < 4; i++) {
      let primitive;
      if (i % 2 === 0) {
        primitive = new DummyAead1();
      } else {
        primitive = new DummyAead2();
      }
      await primitiveSet.addPrimitive(primitive, key);
    }

    const identifier = CryptoFormat.getOutputPrefix(key);
    const primitives = await primitiveSet.getPrimitives(identifier);
    const primary = primitives[0];

    try {
      await primitiveSet.setPrimary(primary);
    } catch (e) {
      assertEquals(ExceptionText.setPrimaryToCollidingEntry(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testSetPrimaryToEntryWithDisabledKeyStatus() {
    const key = createKey(/* opt_keyId = */ 0x12345678,
        /* opt_legacy = */ false, /* opt_enabled = */ false);
    const primitiveSet = new PrimitiveSet.PrimitiveSet();

    const primary = await primitiveSet.addPrimitive(new DummyAead1(), key);

    try {
      await primitiveSet.setPrimary(primary);
    } catch (e) {
      assertEquals(ExceptionText.setPrimaryToDisabled(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testSetAndGetPrimary() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet();
    assertEquals(null, primitiveSet.getPrimary());

    const key1 = createKey(/* opt_keyId = */ 0xBBBCCC);

    const result = await primitiveSet.addPrimitive(new DummyAead1(), key1);
    // Check that primary remains unset, set it to newly added and verify that
    // it was set.
    assertEquals(null, primitiveSet.getPrimary());
    await primitiveSet.setPrimary(result);
    assertObjectEquals(result, primitiveSet.getPrimary());

    const key2 = createKey(/* opt_keyId = */ 0xAAABBB);
    // Add new primitive, check that it does not change primary.
    const result2 = await primitiveSet.addPrimitive(new DummyAead2(), key2);
    assertObjectEquals(result, primitiveSet.getPrimary());

    // Change the primary and verify the change.
    await primitiveSet.setPrimary(result2);
    assertObjectEquals(result2, primitiveSet.getPrimary());
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
  static setPrimaryToCollidingEntry() {
    return 'CustomError: Primary cannot be set to an entry which ' +
        'identifier corresponds to more than one enabled keys.';
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
 * @return {!Promise<!PrimitiveSet.PrimitiveSet>}
 */
const initPrimitiveSet = async function(n) {
  let primitiveSet = new PrimitiveSet.PrimitiveSet();

  // Set primary.
  const primaryKey = createKey(/* opt_id = */ 0, /* opt_legacy = */ false,
      /* opt_enabled = */ true);
  const primary = await primitiveSet.addPrimitive(new DummyAead1(), primaryKey);
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

    await primitiveSet.addPrimitive(primitive, key);
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
