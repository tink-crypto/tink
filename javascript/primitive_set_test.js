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

const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const CryptoFormat = goog.require('tink.CryptoFormat');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const {PbKeyStatusType, PbKeysetKey, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('primitive set test', function() {
  /////////////////////////////////////////////////////////////////////////////
  // tests for addPrimitive method
  it('add primitive unknown crypto format', function() {
    const primitive = new DummyAead1();
    const key =
        createKey().setOutputPrefixType(PbOutputPrefixType.UNKNOWN_PREFIX);
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

    try {
      primitiveSet.addPrimitive(primitive, key);
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownPrefixType());
      return;
    }
    fail('An exception should be thrown.');
  });

  it('add primitive multiple times should work', function() {
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

      expect(result.getPrimitive()).toEqual(primitive);
      expect(result.getKeyStatus()).toBe(key.getStatus());
      expect(result.getOutputPrefixType()).toBe(key.getOutputPrefixType());
      expect(result.getIdentifier()).toEqual(CryptoFormat.getOutputPrefix(key));
    }
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitives method
  it('get primitives which were not added', function() {
    // Fill in the structure with some primitives.
    const numberOfAddedPrimitives = 12;
    const primitiveSet = initPrimitiveSet(numberOfAddedPrimitives);

    const key = createKey(/* opt_keyId = */ numberOfAddedPrimitives + 1);
    const identifier = CryptoFormat.getOutputPrefix(key);
    const result = primitiveSet.getPrimitives(identifier);

    expect(result).toEqual([]);
  });

  it('get primitives different identifiers', function() {
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

      expect(result).toEqual(expectedResult);
    }
  });

  it('get primitives same identifiers', function() {
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

    expect(result).toEqual(expectedResult);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getRawPrimitives method
  it('get raw primitives', function() {
    const numberOfAddedPrimitives = 20;
    const primitiveSet = initPrimitiveSet(numberOfAddedPrimitives);

    // No RAW primitives were added.
    let expectedResult = [];
    let result = primitiveSet.getRawPrimitives();
    expect(result).toEqual(expectedResult);

    // Add RAW primitives and check the result again after each adding.
    let key = createKey().setOutputPrefixType(PbOutputPrefixType.RAW);

    let addResult = primitiveSet.addPrimitive(new DummyAead1(), key);
    expectedResult.push(addResult);
    result = primitiveSet.getRawPrimitives();
    expect(result).toEqual(expectedResult);

    key.setStatus(PbKeyStatusType.DISABLED);
    addResult = primitiveSet.addPrimitive(new DummyAead2(), key);
    expectedResult.push(addResult);
    result = primitiveSet.getRawPrimitives();
    expect(result).toEqual(expectedResult);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for setPrimary and getPrimary methods
  it('set primary to nonholded entry', function() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);
    const entry = new PrimitiveSet.Entry(
        new DummyAead1(), new Uint8Array(10), PbKeyStatusType.ENABLED,
        PbOutputPrefixType.TINK);

    try {
      primitiveSet.setPrimary(entry);
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.setPrimaryToMissingEntry());
      return;
    }
    fail('An exception should be thrown.');
  });

  it('set primary to entry with disabled key status', function() {
    const key = createKey(/* opt_keyId = */ 0x12345678,
        /* opt_legacy = */ false, /* opt_enabled = */ false);
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);

    const primary = primitiveSet.addPrimitive(new DummyAead1(), key);

    try {
      primitiveSet.setPrimary(primary);
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.setPrimaryToDisabled());
      return;
    }
    fail('An exception should be thrown.');
  });

  it('set and get primary', function() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);
    expect(primitiveSet.getPrimary()).toBe(null);

    const key1 = createKey(/* opt_keyId = */ 0xBBBCCC);

    const result = primitiveSet.addPrimitive(new DummyAead1(), key1);
    // Check that primary remains unset, set it to newly added and verify that
    // it was set.
    expect(primitiveSet.getPrimary()).toBe(null);
    primitiveSet.setPrimary(result);
    expect(primitiveSet.getPrimary()).toEqual(result);

    const key2 = createKey(/* opt_keyId = */ 0xAAABBB);
    // Add new primitive, check that it does not change primary.
    const result2 = primitiveSet.addPrimitive(new DummyAead2(), key2);
    expect(primitiveSet.getPrimary()).toEqual(result);

    // Change the primary and verify the change.
    primitiveSet.setPrimary(result2);
    expect(primitiveSet.getPrimary()).toEqual(result2);
  });

  it('set primary, raw primitives', function() {
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
  });

  it('get primary type', function() {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(Aead);
    expect(primitiveSet.getPrimitiveType()).toEqual(Aead);
  });
});

// Helper classes and functions used for testing purposes.
class ExceptionText {
  /** @return {string} */
  static unknownPrefixType() {
    return 'SecurityException: Unsupported key prefix type.';
  }

  /** @return {string} */
  static addingNullPrimitive() {
    return 'SecurityException: Primitive has to be non null.';
  }

  /** @return {string} */
  static addingNullKey() {
    return 'SecurityException: Key has to be non null.';
  }

  /** @return {string} */
  static setPrimaryToNull() {
    return 'SecurityException: Primary cannot be set to null.';
  }

  /** @return {string} */
  static setPrimaryToMissingEntry() {
    return 'SecurityException: Primary cannot be set to an entry which is ' +
        'not held by this primitive set.';
  }

  /** @return {string} */
  static setPrimaryToDisabled() {
    return 'SecurityException: Primary has to be enabled.';
  }
}

/**
 * @final
 */
class DummyAead1 extends Aead {
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
 * @final
 */
class DummyAead2 extends Aead {
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
