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

goog.module('tink.testUtils');
goog.setTestOnly();

const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');

/**
 * Creates a key for testing purposes. Generates a new key with id, output
 * prefix type and status given by optional arguments. The default values are
 * the following: id = 0x12345678, output prefix type = TINK, and status =
 * ENABLED.
 *
 * @param {number=} keyId
 * @param {boolean=} legacy
 * @param {boolean=} enabled
 *
 * @return{!PbKeyset.Key}
 */
const createKey = function(keyId = 0x12345678, legacy = false, enabled = true) {
  const key = new PbKeyset.Key();

  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  if (legacy) {
    key.setOutputPrefixType(PbOutputPrefixType.LEGACY);
  } else {
    key.setOutputPrefixType(PbOutputPrefixType.TINK);
  }

  key.setKeyId(keyId);

  const keyData = new PbKeyData()
                      .setTypeUrl('someTypeUrl')
                      .setValue(new Uint8Array(10))
                      .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  key.setKeyData(keyData);

  return key;
};

/**
 * Returns a valid PbKeyset whose primary key has id equal to 1.
 *
 * @param {number=} keysetSize
 *
 * @return {!PbKeyset}
 */
const createKeyset = function(keysetSize = 20) {
  const keyset = new PbKeyset();
  for (let i = 0; i < keysetSize; i++) {
    const key = createKey(
        i + 1, /* legacy = */ (i % 2) < 1,
        /* enabled = */ (i % 4) < 2);
    keyset.addKey(key);
  }

  keyset.setPrimaryKeyId(1);
  return keyset;
};

exports = {
  createKey,
  createKeyset,
};
