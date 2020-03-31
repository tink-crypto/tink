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

goog.module('tink.CryptoFormat');

const {InvalidArgumentsException} = goog.require('google3.third_party.tink.javascript.exception.invalid_arguments_exception');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const {PbKeyset, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

/**
 * Constants and methods that deal with the format of the outputs handled by
 * Tink.
 *
 * @static
 * @final
 */
class CryptoFormat {
  /**
   * Generates the prefix for the outputs handled by the given 'key'.
   * Throws an exception if the prefix type of 'key' is invalid.
   *
   * @param {PbKeyset.Key} key
   *
   * @return {!Uint8Array}
   */
  static getOutputPrefix(key) {
    switch (key.getOutputPrefixType()) {
      case PbOutputPrefixType.LEGACY: // fall through
      case PbOutputPrefixType.CRUNCHY:
        return CryptoFormat.makeOutputPrefix_(
            key.getKeyId(), CryptoFormat.LEGACY_START_BYTE);
      case PbOutputPrefixType.TINK:
        return CryptoFormat.makeOutputPrefix_(
            key.getKeyId(), CryptoFormat.TINK_START_BYTE);
      case PbOutputPrefixType.RAW:
        return CryptoFormat.RAW_PREFIX;
      default:
        throw new SecurityException('Unsupported key prefix type.');
    }
  }

  /**
   * Makes output prefix which consits of 4 bytes of key id in Big Endian
   * representation followed by 1 byte of key type identifier.
   *
   * @static
   * @private
   * @param {number} keyId
   * @param {number} keyTypeIdentifier
   *
   * @return {!Uint8Array}
   */
  static makeOutputPrefix_(keyId, keyTypeIdentifier) {
    let /** Array */ res = [keyTypeIdentifier];
    res = res.concat(CryptoFormat.numberAsBigEndian_(keyId));
    return new Uint8Array(res);
  }


  /**
   * Returns the given number as Uint8Array in Big Endian format.
   *
   * Given number has to be a non-negative integer smaller than 2^32.
   *
   * @static
   * @private
   * @param {number} n
   *
   * @return {!Array}
   */
  static numberAsBigEndian_(n) {
    if (!Number.isInteger(n) || n < 0 || n >= 2**32) {
      throw new InvalidArgumentsException(
          'Number has to be unsigned 32-bit integer.');
    }
    const numberOfBytes = 4;
    let res = new Array(numberOfBytes);
    for (let i = 0; i < numberOfBytes; i++) {
      res[i] = 0xFF & (n >> 8 * (numberOfBytes - i - 1));
    }
    return res;
  }
}

/**
 * Prefix size of Tink and Legacy key types.
 * @const @static {number}
 */
CryptoFormat.NON_RAW_PREFIX_SIZE = 5;

/**
 * Prefix size of Legacy key types.
 * @const @static {number}
 */
CryptoFormat.LEGACY_PREFIX_SIZE = CryptoFormat.NON_RAW_PREFIX_SIZE;
/**
 * Legacy starts with 0 and is followed by 4-byte key id.
 * @const @static {number}
 */
CryptoFormat.LEGACY_START_BYTE = 0x00;

/**
 * Prefix size of Tink key types.
 * @const @static {number}
 */
CryptoFormat.TINK_PREFIX_SIZE = CryptoFormat.NON_RAW_PREFIX_SIZE;
/**
 * Tink starts with 1 and is followed by 4-byte key id.
 * @const @static {number}
 */
CryptoFormat.TINK_START_BYTE = 0x01;

/**
 * Raw prefix should have length 0.
 * @const @static {number}
 */
CryptoFormat.RAW_PREFIX_SIZE = 0;
/**
 * Raw prefix is empty Uint8Array.
 * @const @static
 * @type {!Uint8Array}
 */
CryptoFormat.RAW_PREFIX = new Uint8Array(0);

exports = CryptoFormat;
