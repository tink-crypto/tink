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

/**
 * Does near constant time byte array comparison.
 * @param {!Uint8Array} ba1 The first bytearray to check.
 * @param {!Uint8Array} ba2 The second bytearray to check.
 * @return {boolean} If the array are equal.
 */
const isEqual = function(ba1, ba2) {
  if (ba1.length !== ba2.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < ba1.length; i++) {
    result |= ba1[i] ^ ba2[i];
  }
  return result == 0;
};


/**
 * Returns a new array that is the result of joining the arguments.
 * @param {...!Uint8Array} var_args
 * @return {!Uint8Array}
 */
const concat = function(var_args) {
  let length = 0;
  for (let i = 0; i < arguments.length; i++) {
    length += arguments[i].length;
  }
  let result = new Uint8Array(length);
  let curOffset = 0;
  for (let i = 0; i < arguments.length; i++) {
    result.set(arguments[i], curOffset);
    curOffset += arguments[i].length;
  }
  return result;
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
  let low = value % two_power_32;
  let high = value / two_power_32;
  const result = new Uint8Array(8);
  for (let i = 7; i >= 4; i--) {
    result[i] = low & 0xff;
    low >>>= 8;
  }
  for (let i = 3; i >= 0; i--) {
    result[i] = high & 0xff;
    high >>>= 8;
  }
  return result;
};

/**
 * Converts the hex string to a byte array.
 *
 * @param {string} hex the input
 * @return {!Uint8Array} the byte array output
 * @throws {!InvalidArgumentsException}
 * @static
 */
const fromHex = function(hex) {
  if (hex.length % 2 != 0) {
    throw new InvalidArgumentsException(
        'Hex string length must be multiple of 2');
  }
  var arr = new Uint8Array(hex.length / 2);
  for (var i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return arr;
};

/**
 * Converts a byte array to hex.
 *
 * @param {!Uint8Array} bytes the byte array input
 * @return {string} hex the output
 * @static
 */
const toHex = function(bytes) {
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    let hexByte = bytes[i].toString(16);
    result += hexByte.length > 1 ? hexByte : '0' + hexByte;
  }
  return result;
};

/**
 * Converts the Base64 string to a byte array.
 *
 * @param {string} encoded the base64 string
 * @param {boolean=} opt_webSafe True indicates we should use the alternative
 *     alphabet, which does not require escaping for use in URLs.
 * @return {!Uint8Array} the byte array output
 * @static
 */
const fromBase64 = function(encoded, opt_webSafe) {
  if (opt_webSafe) {
    const normalBase64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    return fromByteString(window.atob(normalBase64));
  }
  return fromByteString(window.atob(encoded));
};

/**
 * Base64 encode a byte array.
 *
 * @param {!Uint8Array} bytes the byte array input
 * @param {boolean=} opt_webSafe True indicates we should use the alternative
 *     alphabet, which does not require escaping for use in URLs.
 * @return {string} base64 output
 * @static
 */
const toBase64 = function(bytes, opt_webSafe) {
  let encoded =
      window.btoa(toByteString(bytes)).replace(/=/g, '') /* padding */;
  if (opt_webSafe) {
    return encoded.replace(/\+/g, '-').replace(/\//g, '_');
  }
  return encoded;
};

/**
 * Converts a byte string to a byte array. Only support ASCII and Latin-1
 * strings, does not support multi-byte characters.
 *
 * @param {string} str the input
 * @return {!Uint8Array} the byte array output
 * @static
 */
const fromByteString = function(str) {
  let output = [];
  let p = 0;
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    output[p++] = c;
  }
  return new Uint8Array(output);
};

/**
 * Turns a byte array into the string given by the concatenation of the
 * characters to which the numbers correspond. Each byte is corresponding to a
 * character. Does not support multi-byte characters.
 *
 * @param {!Uint8Array} bytes Array of numbers representing
 *     characters.
 * @return {string} Stringification of the array.
 */
const toByteString = function(bytes) {
  var str = '';
  for (var i = 0; i < bytes.length; i += 1) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
};

exports = {
  concat,
  fromBase64,
  fromHex,
  fromNumber,
  fromByteString,
  isEqual,
  toBase64,
  toHex,
  toByteString,
};
