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

goog.module('tink.NoSecretKeysetHandleTest');
goog.setTestOnly('tink.NoSecretKeysetHandleTest');

const BinaryKeysetReader = goog.require('tink.BinaryKeysetReader');
const NoSecretKeysetHandle = goog.require('tink.NoSecretKeysetHandle');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyMaterialType = goog.require('proto.google.crypto.tink.KeyData.KeyMaterialType');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const Random = goog.require('tink.subtle.Random');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  testRead_nullReader() {
    try {
      NoSecretKeysetHandle.read(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.nullReader(), e.toString());
    }
  },

  testRead_keysetContainingSecretKeyMaterial() {
    const secretKeyMaterialTypes = [
      PbKeyMaterialType.SYMMETRIC, PbKeyMaterialType.ASYMMETRIC_PRIVATE,
      PbKeyMaterialType.UNKNOWN_KEYMATERIAL
    ];
    for (let secretKeyMaterialType of secretKeyMaterialTypes) {
      const keyset = createKeyset();
      const key = createKeysetKey(
          /* keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
          secretKeyMaterialType, /* enabled = */ true);
      keyset.addKey(key);
      const reader =
          BinaryKeysetReader.withUint8Array(keyset.serializeBinary());
      try {
        NoSecretKeysetHandle.read(reader);
        fail('An exception should be thrown.');
      } catch (e) {
        assertEquals(ExceptionText.secretKeyMaterial(), e.toString());
      }
    }
  },

  testRead_shouldWork() {
    const keyset = createKeyset();
    const reader = BinaryKeysetReader.withUint8Array(keyset.serializeBinary());
    const keysetHandle = NoSecretKeysetHandle.read(reader);
    assertObjectEquals(keyset, keysetHandle.getKeyset());
  },
});


// Helper classes and functions used for testing purposes.
class ExceptionText {
  /** @return {string} */
  static nullReader() {
    return 'CustomError: Reader has to be non-null.';
  }
  /** @return {string} */
  static secretKeyMaterial() {
    return 'CustomError: Keyset contains secret key material.';
  }
}

/**
 * Function for creating keys for testing purposes.
 *
 * @param {number} keyId
 * @param {PbOutputPrefixType} outputPrefix
 * @param {PbKeyMaterialType} keyMaterialType
 * @param {boolean} enabled
 *
 * @return {!PbKeyset.Key}
 */
const createKeysetKey = function(
    keyId, outputPrefix, keyMaterialType, enabled) {
  let key = new PbKeyset.Key();

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
  key.getKeyData().setKeyMaterialType(keyMaterialType);
  key.getKeyData().setValue(Random.randBytes(10));

  return key;
};

/**
 * Returns a valid PbKeyset which primary key has id equal to 1.
 *
 * @param {number=} opt_keysetSize
 * @return {!PbKeyset}
 */
const createKeyset = function(opt_keysetSize = 20) {
  const keyset = new PbKeyset();
  for (let i = 0; i < opt_keysetSize; i++) {
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
    const key = createKeysetKey(
        /* keyId = */ i + 1, outputPrefix, PbKeyMaterialType.ASYMMETRIC_PUBLIC,
        /* opt_enabled = */ (i % 4) < 2);
    keyset.addKey(key);
  }
  keyset.setPrimaryKeyId(1);
  return keyset;
};
