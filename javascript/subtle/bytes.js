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

goog.module('tink.subtle.Bytes');

const crypt = goog.require('goog.crypt');

/**
 * Does near constant time byte array comparison.
 * @param {!Uint8Array} ba1 The first bytearray to check.
 * @param {!Uint8Array} ba2 The second bytearray to check.
 * @return {boolean} If the array are equal.
 */
const compare = function(ba1, ba2) {
  if (ba1.length !== ba2.length) {
    return false;
  }
  var yes = 1;
  for (var i = 0; i < ba1.length; i++) {
    yes &= !(ba1[i] ^ ba2[i]) | 0;
  }
  return yes == 1;
};


/**
 * Returns a new array that is the result of joining the arguments.
 * @param {...!Uint8Array} var_args
 * @return {!Uint8Array}
 * @private
 */
const concat = function(var_args) {
  var length = 0;
  for (var i = 0; i < arguments.length; i++) {
    length += arguments[i].length;
  }
  var result = new Uint8Array(length);
  var curOffset = 0;
  for (var i = 0; i < arguments.length; i++) {
    result.set(arguments[i], curOffset);
    curOffset += arguments[i].length;
  }
  return result;
};

/**
 * Converts the hex string to a byte array.
 *
 * @param {string} hex the input
 * @return {!Uint8Array} the byte array output
 * @static
 */
const fromHex = function(hex) {
  return new Uint8Array(crypt.hexToByteArray(hex));
};

/**
 * Converts a byte array to hex.
 *
 * @param {!Uint8Array} bytes the byte array input
 * @return {string} hex the output
 * @static
 */
const toHex = function(bytes) {
  return crypt.byteArrayToHex(bytes);
};

exports = {
  compare,
  concat,
  fromHex,
  toHex,
};
