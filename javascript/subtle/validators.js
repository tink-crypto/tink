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

goog.module('tink.subtle.Validators');

const {InvalidArgumentsException} = goog.require('google3.third_party.tink.javascript.exception.invalid_arguments_exception');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');

/**
 * @const @public {!Array.<number>}
 */
const SUPPORTED_AES_KEY_SIZES = [16, 32];

/**
 * Validates AES key sizes, at the moment only 128-bit and 256-bit keys are
 * supported.
 *
 * @param {number} n the key size in bytes
 * @throws {!InvalidArgumentsException}
 * @static
 */
const validateAesKeySize = function(n) {
  if (!SUPPORTED_AES_KEY_SIZES.includes(n)) {
    throw new InvalidArgumentsException('unsupported AES key size: ' + n);
  }
};

/**
 * Validates that the input is a non null Uint8Array.
 *
 * @param {!Uint8Array} input
 * @throws {!InvalidArgumentsException}
 * @static
 */
const requireUint8Array = function(input) {
  if (input == null || !(input instanceof Uint8Array)) {
    throw new InvalidArgumentsException('input must be a non null Uint8Array');
  }
};

/**
 * Validates version, throws exception if candidate version is negative or
 * bigger than expected.
 *
 * @param {number} candidate - version to be validated
 * @param {number} maxVersion - upper bound on version
 * @throws {!SecurityException}
 * @static
 */
const validateVersion = function(candidate, maxVersion) {
  if (candidate < 0 || candidate > maxVersion) {
    throw new SecurityException(
        'Version is out of bound, must be ' +
        'between 0 and ' + maxVersion + '.');
  }
};

/**
 * Validates ECDSA parameters.
 *
 * @param {string} curve
 * @param {string} hash
 * @throws {!SecurityException}
 */
const validateEcdsaParams = function(curve, hash) {
  switch (curve) {
    case 'P-256':
      if (hash != 'SHA-256') {
        throw new SecurityException(
            'expected SHA-256 (because curve is P-256) but got ' + hash);
      }
      break;
    case 'P-384':
      if (hash != 'SHA-384' && hash != 'SHA-512') {
        throw new SecurityException(
            'expected SHA-384 or SHA-512 (because curve is P-384) but got ' +
            hash);
      }
      break;
    case 'P-521':
      if (hash != 'SHA-512') {
        throw new SecurityException(
            'expected SHA-512 (because curve is P-521) but got ' + hash);
      }
      break;
    default:
      throw new SecurityException('unsupported curve: ' + curve);
  }
};

exports = {
  validateAesKeySize,
  validateEcdsaParams,
  requireUint8Array,
  validateVersion
};
