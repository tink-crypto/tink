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

const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');

/**
 * @const @public {Array.<number>}
 */
const SUPPORTED_AES_KEY_SIZES = [16, 32];

/**
 * Validate AES key sizes, at the moment only 128-bit and 256-bit keys are
 * supported.
 *
 * @param {number} n the key size in bytes
 * @throws {InvalidArgumentsException}
 * @static
 */
const validateAesKeySize = function(n) {
  if (!SUPPORTED_AES_KEY_SIZES.includes(n)) {
    throw new InvalidArgumentsException('unsupported AES key size: ' + n);
  }
};

exports = {validateAesKeySize};
