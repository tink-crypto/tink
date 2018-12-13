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

goog.module('tink.UtilTest');
goog.setTestOnly('tink.UtilTest');

const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const PbPointFormat = goog.require('proto.google.crypto.tink.EcPointFormat');
const Util = goog.require('tink.Util');

const testSuite = goog.require('goog.testing.testSuite');

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

testSuite({
  // tests for validateKey method
  async testValidateKeyMissingKeyData() {
    const key = createKey();
    key.setKeyData(null);

    try {
      await Util.validateKey(key);
    } catch (e) {
      assertEquals(
          ExceptionText.InvalidKeyMissingKeyData(key.getKeyId()), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testValidateKeyUnknownPrefix() {
    const key = createKey();
    key.setOutputPrefixType(PbOutputPrefixType.UNKNOWN_PREFIX);

    try {
      await Util.validateKey(key);
    } catch (e) {
      assertEquals(
          ExceptionText.InvalidKeyUnknownPrefix(key.getKeyId()), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testValidateKeyUnknownStatus() {
    const key = createKey();
    key.setStatus(PbKeyStatusType.UNKNOWN_STATUS);

    try {
      await Util.validateKey(key);
    } catch (e) {
      assertEquals(
          ExceptionText.InvalidKeyUnknownStatus(key.getKeyId()), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testValidateKeyValidKeys() {
    await Util.validateKey(createKey());
    await Util.validateKey(
        createKey(/* opt_keyId = */ 0xAABBCCDD, /* opt_enabled = */ true));
    await Util.validateKey(
        createKey(/* opt_keyId = */ 0xABCDABCD, /* opt_enabled = */ false));
  },

  // tests for validateKeyset method
  async testValidateKeysetWithoutKeys() {
    const keyset = new PbKeyset();

    try {
      await Util.validateKeyset(keyset);
    } catch (e) {
      assertEquals(ExceptionText.InvalidKeysetMissingKeys(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testValidateKeysetDisabledPrimary() {
    const keyset = createKeyset();
    keyset.addKey(
        createKey(/* opt_id = */ 0xFFFFFFFF, /* opt_enabled = */ false));
    keyset.setPrimaryKeyId(0xFFFFFFFF);

    try {
      await Util.validateKeyset(keyset);
    } catch (e) {
      assertEquals(ExceptionText.InvalidKeysetDisabledPrimary(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testValidateKeysetMultiplePrimaries() {
    const keyset = createKeyset();
    const key =
        createKey(/* opt_id = */ 0xFFFFFFFF, /* opt_enabled = */ true);
    keyset.addKey(key);
    keyset.addKey(key);
    keyset.setPrimaryKeyId(0xFFFFFFFF);

    try {
      await Util.validateKeyset(keyset);
    } catch (e) {
      assertEquals(
          ExceptionText.InvalidKeysetMultiplePrimaries(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testValidateKeysetWithInvalidKey() {
    const keyset = createKeyset();
    const key =
        createKey(/* opt_id = */ 0xFFFFFFFF, /* opt_enabled = */ true);
    key.setStatus(PbKeyStatusType.UNKNOWN_STATUS);
    keyset.addKey(key);

    try {
      await Util.validateKeyset(keyset);
    } catch (e) {
      assertEquals(
          ExceptionText.InvalidKeyUnknownStatus(key.getKeyId()), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testValidateKeysetWithValidKeyset() {
    const keyset = createKeyset();

    await Util.validateKeyset(keyset);
  },

  // tests for protoToSubtle methods
  testCurveTypeProtoToSubtle() {
    assertEquals(
        EllipticCurves.CurveType.P256,
        Util.curveTypeProtoToSubtle(PbEllipticCurveType.NIST_P256));
    assertEquals(
        EllipticCurves.CurveType.P384,
        Util.curveTypeProtoToSubtle(PbEllipticCurveType.NIST_P384));
    assertEquals(
        EllipticCurves.CurveType.P521,
        Util.curveTypeProtoToSubtle(PbEllipticCurveType.NIST_P521));
  },

  testPointFormatProtoToSubtle() {
    assertEquals(
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        Util.pointFormatProtoToSubtle(PbPointFormat.UNCOMPRESSED));
    assertEquals(
        EllipticCurves.PointFormatType.COMPRESSED,
        Util.pointFormatProtoToSubtle(PbPointFormat.COMPRESSED));
    assertEquals(
        EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
        Util.pointFormatProtoToSubtle(
            PbPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
  },

  testHashTypeProtoToString() {
    assertEquals('SHA-1', Util.hashTypeProtoToString(PbHashType.SHA1));
    assertEquals('SHA-256', Util.hashTypeProtoToString(PbHashType.SHA256));
    assertEquals('SHA-512', Util.hashTypeProtoToString(PbHashType.SHA512));
  },
});


/**
 * Class which holds texts for each type of exception.
 * @final
 */
class ExceptionText {
  // Exceptions for invalid keys.
  /**
   * @param {number} keyId
   *
   * @return {string}
   */
  static InvalidKeyMissingKeyData(keyId) {
    return 'CustomError: Key data are missing for key ' + keyId + '.';
  }
  /**
   * @param {number} keyId
   *
   * @return {string}
   */
  static InvalidKeyUnknownPrefix(keyId) {
    return 'CustomError: Key ' + keyId + ' has unknown output prefix type.';
  }
  /**
   * @param {number} keyId
   *
   * @return {string}
   */
  static InvalidKeyUnknownStatus(keyId) {
    return 'CustomError: Key ' + keyId + ' has unknown status.';
  }

  // Exceptions for invalid keysets.
  /** @return {string} */
  static InvalidKeysetMissingKeys() {
    return 'CustomError: Keyset should be non null and ' +
        'must contain at least one key.';
  }
  /** @return {string} */
  static InvalidKeysetDisabledPrimary() {
    return 'CustomError: Primary key has to be in the keyset and ' +
        'has to be enabled.';
  }
  /** @return {string} */
  static InvalidKeysetMultiplePrimaries() {
    return 'CustomError: Primary key has to be unique.';
  }
}

/**
 * Returns a valid PbKeyset.Key.
 *
 * @param {number=} opt_id
 * @param {boolean=} opt_enabled
 * @param {boolean=} opt_publicKey
 *
 * @return {!PbKeyset.Key}
 */
const createKey = function(opt_id = 0x12345678, opt_enabled = true,
    opt_publicKey = false) {
  const keyData = new PbKeyData();
  keyData.setTypeUrl('someTypeUrl');
  keyData.setValue(new Uint8Array(10));
  if (opt_publicKey) {
    keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
  } else {
    keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  }

  const key = new PbKeyset.Key();
  key.setKeyData(keyData);
  if (opt_enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }
  key.setKeyId(opt_id);
  key.setOutputPrefixType(PbOutputPrefixType.TINK);

  return key;
};

/**
 * Returns a valid PbKeyset which primary has id equal to 1.
 *
 * @return {!PbKeyset}
 */
const createKeyset = function() {
  const numberOfKeys = 20;

  const keyset = new PbKeyset();
  for (let i = 0; i < numberOfKeys; i++) {
    // Key id is never set to 0 as primaryKeyId = 0 if it is unset.
    const key = createKey(i + 1, /* opt_enabled = */ (i % 2) < 1, (i % 4) < 2);
    keyset.addKey(key);
  }

  keyset.setPrimaryKeyId(1);
  return keyset;
};
