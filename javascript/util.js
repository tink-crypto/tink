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

goog.module('tink.Util');

const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * Validates the given key and throws SecurityException if it is invalid.
 *
 * @param {!PbKeyset.Key} key
 */
const validateKey = function(key) {
  if (!key) {
    throw new SecurityException('Key should be non null.');
  }
  if (!key.getKeyData()) {
    throw new SecurityException('Key data are missing for key '
        + key.getKeyId() + '.');
  }
  if (key.getOutputPrefixType() === PbOutputPrefixType.UNKNOWN_PREFIX) {
    throw new SecurityException('Key ' + key.getKeyId() +
        ' has unknown output prefix type.');
  }
  if (key.getStatus() === PbKeyStatusType.UNKNOWN_STATUS) {
    throw new SecurityException('Key ' + key.getKeyId() +
        ' has unknown status.');
  }
};

/**
 * Validates the given keyset and throws SecurityException if it is invalid.
 *
 * @param {!PbKeyset} keyset
 */
const validateKeyset = function(keyset) {
  if (!keyset || !keyset.getKeyList() || keyset.getKeyList().length < 1) {
    throw new SecurityException(
        'Keyset should be non null and must contain at least one key.');
  }

  let hasPrimary = false;
  const numberOfKeys = keyset.getKeyList().length;
  for (let i = 0; i < numberOfKeys; i++) {
    const key = keyset.getKeyList()[i];
    validateKey(key);
    if (keyset.getPrimaryKeyId() === key.getKeyId() &&
        key.getStatus() === PbKeyStatusType.ENABLED) {
      if (hasPrimary) {
        throw new SecurityException('Primary key has to be unique.');
      }
      hasPrimary = true;
    }
  }

  if (!hasPrimary) {
    throw new SecurityException('Primary key has to be in the keyset and ' +
        'has to be enabled.');
  }
};

exports = {
  validateKey,
  validateKeyset,
};
