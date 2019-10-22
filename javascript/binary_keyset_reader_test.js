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

goog.module('tink.BinaryKeysetReaderTest');
goog.setTestOnly('tink.BinaryKeysetReaderTest');

const BinaryKeysetReader = goog.require('tink.BinaryKeysetReader');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbKeysetKey = goog.require('proto.google.crypto.tink.Keyset.Key');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const Random = goog.require('tink.subtle.Random');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testWithSerializedKeyset_nullSerializedProto() {
    try {
      BinaryKeysetReader.withUint8Array(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.nullKeyset(), e.toString());
    }
  },

  testRead_invalidSerializedKeysetProto() {
    for (let i = 0; i < 2; i++) {
      // The Uint8Array is not a serialized keyset.
      const reader = BinaryKeysetReader.withUint8Array(new Uint8Array(i));

      try {
        reader.read();
        fail('An exception should be thrown.');
      } catch (e) {
        assertEquals(ExceptionText.invalidSerialization(), e.toString());
      }
    }
  },

  testRead() {
    // Create keyset proto and serialize it.
    const keyset = new PbKeyset();
    // The for cycle starts from 1 as setting any proto value to 0 sets it to
    // null and after serialization and deserialization null is changed to
    // undefined and the assertion at the end fails (unless you compare the
    // keyset and newly created keyset value by value).
    for (let i = 1; i < 20; i++) {
      let outputPrefix;
      switch (i % 3) {
        case 0:
          outputPrefix = PbOutputPrefixType.TINK;
          break;
        case 1:
          outputPrefix = PbOutputPrefixType.RAW;
          break;
        default:
          outputPrefix = PbOutputPrefixType.LEGACY;
      }
      keyset.addKey(createDummyKeysetKey(
          /* keyId = */ i, outputPrefix, /* enabled = */ i % 4 < 3));
    }
    keyset.setPrimaryKeyId(1);

    const serializedKeyset = keyset.serializeBinary();

    // Read the keyset proto serialization.
    const reader = BinaryKeysetReader.withUint8Array(serializedKeyset);
    const keysetFromReader = reader.read();

    // Test that it returns the same object as was created.
    assertObjectEquals(keyset, keysetFromReader);
  },

  testReadEncrypted_notImplementedYet() {
    const reader = BinaryKeysetReader.withUint8Array(new Uint8Array(10));

    try {
      reader.readEncrypted();
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.notImplemented(), e.toString());
    }
  },
});

////////////////////////////////////////////////////////////////////////////////
// helper functions and classes for tests
////////////////////////////////////////////////////////////////////////////////

/**
 * Class which holds texts for each type of exception.
 * @final
 */
class ExceptionText {
  /** @return {string} */
  static notImplemented() {
    return 'CustomError: Not implemented yet.';
  }
  /** @return {string} */
  static nullKeyset() {
    return 'CustomError: Serialized keyset has to be non-null.';
  }
  /** @return {string} */
  static invalidSerialization() {
    return 'CustomError: Could not parse the given serialized proto as ' +
        'a keyset proto.';
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

  // Set some key data.
  key.setKeyData(new PbKeyData());
  key.getKeyData().setTypeUrl('SOME_KEY_TYPE_URL_' + keyId.toString());
  key.getKeyData().setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  key.getKeyData().setValue(Random.randBytes(10));

  return key;
};
