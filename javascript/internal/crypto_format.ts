/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';
import {SecurityException} from '../exception/security_exception';

import {PbKeysetKey, PbOutputPrefixType} from './proto';

/**
 * Constants and methods that deal with the format of the outputs handled by
 * Tink.
 *
 * @static
 * @final
 */
export class CryptoFormat {
  /**
   * Generates the prefix for the outputs handled by the given 'key'.
   * Throws an exception if the prefix type of 'key' is invalid.
   *
   *
   */
  static getOutputPrefix(key: PbKeysetKey): Uint8Array {
    switch (key.getOutputPrefixType()) {
      case PbOutputPrefixType.LEGACY:

      // fall through
      case PbOutputPrefixType.CRUNCHY:
        return CryptoFormat.makeOutputPrefix(
            key.getKeyId(), CryptoFormat.LEGACY_START_BYTE);
      case PbOutputPrefixType.TINK:
        return CryptoFormat.makeOutputPrefix(
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
   *
   */
  private static makeOutputPrefix(keyId: number, keyTypeIdentifier: number):
      Uint8Array {
    let res = [keyTypeIdentifier];
    res = res.concat(CryptoFormat.numberAsBigEndian(keyId));
    return new Uint8Array(res);
  }

  /**
   * Returns the given number as Uint8Array in Big Endian format.
   *
   * Given number has to be a non-negative integer smaller than 2^32.
   *
   * @static
   *
   */
  private static numberAsBigEndian(n: number): number[] {
    if (!Number.isInteger(n) || n < 0 || n >= 2 ** 32) {
      throw new InvalidArgumentsException(
          'Number has to be unsigned 32-bit integer.');
    }
    const numberOfBytes = 4;
    const res = new Array(numberOfBytes);
    for (let i = 0; i < numberOfBytes; i++) {
      res[i] = 255 & n >> 8 * (numberOfBytes - i - 1);
    }
    return res;
  }

  /**
   * Prefix size of Tink and Legacy key types.
   */
  static readonly NON_RAW_PREFIX_SIZE = 5;

  /**
   * Prefix size of Legacy key types.
   */
  static readonly LEGACY_PREFIX_SIZE = CryptoFormat.NON_RAW_PREFIX_SIZE;

  /**
   * Legacy starts with 0 and is followed by 4-byte key id.
   */
  static readonly LEGACY_START_BYTE = 0;

  /**
   * Prefix size of Tink key types.
   */
  static readonly TINK_PREFIX_SIZE = CryptoFormat.NON_RAW_PREFIX_SIZE;

  /**
   * Tink starts with 1 and is followed by 4-byte key id.
   */
  static readonly TINK_START_BYTE = 1;

  /**
   * Raw prefix should have length 0.
   */
  static readonly RAW_PREFIX_SIZE = 0;

  /**
   * Raw prefix is empty Uint8Array.
   */
  static readonly RAW_PREFIX = new Uint8Array(0);
}
