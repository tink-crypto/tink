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

goog.module('tink.NoSecretKeysetHandle');

const KeysetHandle = goog.require('tink.KeysetHandle');
const KeysetReader = goog.require('tink.KeysetReader');
const PbKeyMaterialType = goog.require('proto.google.crypto.tink.KeyData.KeyMaterialType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * Static methods for reading cleartext keyset that do not contain any secret
 * key material.
 *
 * @final
 */
class NoSecretKeysetHandle {
  /**
   * Return a new keyset handle obtained from a keyset from the reader.
   *
   * @param {!KeysetReader} reader
   * @return {!KeysetHandle}
   */
  static read(reader) {
    if (reader === null) {
      throw new SecurityException('Reader has to be non-null.');
    }
    const keyset = reader.read();
    NoSecretKeysetHandle.validate_(keyset);
    return new KeysetHandle(keyset);
  }

  /**
   * Validates that the keyset does not contain any secret key material.
   *
   * @param {!PbKeyset} keyset
   * @private
   */
  static validate_(keyset) {
    const keyList = keyset.getKeyList();
    for (let key of keyList) {
      switch (key.getKeyData().getKeyMaterialType()) {
        case PbKeyMaterialType.ASYMMETRIC_PUBLIC:  // fall through
        case PbKeyMaterialType.REMOTE:
          continue;
      }
      throw new SecurityException('Keyset contains secret key material.');
    }
  }
}

exports = NoSecretKeysetHandle;
