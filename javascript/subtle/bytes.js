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

const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
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
 * Converts a non-negative integer number to a 64-bit big-endian byte array.
 * @param {number} value The number to convert.
 * @return {!Uint8Array} The number as a big-endian byte array.
 * @throws {InvalidArgumentsException}
 * @static
 */
const fromNumber = function(value) {
  if (isNaN(value) || value % 1 !== 0) {
    throw new InvalidArgumentsException('cannot convert non-integer value');
  }
  if (value < 0) {
    throw new InvalidArgumentsException('cannot convert negative number');
  }
  if (value > Number.MAX_SAFE_INTEGER) {
    throw new InvalidArgumentsException(
        'cannot convert number larger than ' + Number.MAX_SAFE_INTEGER);
  }
  const two_power_32 = 2**32;
  var low = value % two_power_32;
  var high = value / two_power_32;
  const result = new Uint8Array(8);
  for (var i = 7; i >= 4; i--) {
    result[i] = low & 0xff;
    low >>>= 8;
  }
  for (var i = 3; i >= 0; i--) {
    result[i] = high & 0xff;
    high >>>= 8;
  }
  return result;
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
  fromNumber,
  toHex,
};
