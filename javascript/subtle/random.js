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

/**
 * @fileoverview Several simple wrappers of crypto.getRandomValues.
 * @public
 */

goog.module('tink.subtle.Random');

const {InvalidArgumentsException} = goog.require('google3.third_party.tink.javascript.exception.invalid_arguments_exception');

/**
 * Randomly generates `n` bytes.
 *
 * @param {number} n number of bytes to generate
 * @return {!Uint8Array} the random bytes
 * @static
 */
const randBytes = function(n) {
  if (!Number.isInteger(n) || n < 0) {
    throw new InvalidArgumentsException('n must be a nonnegative integer');
  }
  const result = new Uint8Array(n);
  crypto.getRandomValues(result);
  return result;
};

exports = {randBytes};
