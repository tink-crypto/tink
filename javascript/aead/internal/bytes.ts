/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../exception/invalid_arguments_exception';

/**
 * TODO(b/201071402#comment8): This file is copied (and pruned) from
 * javascript/subtle/bytes in order to solve a circular dependency in the short
 * term. This file should be deleted in the future once the circular dependency
 * is resolved.
 */

/**
 * Returns a new array that is the result of joining the arguments.
 */
export function concat(...var_args: Uint8Array[]): Uint8Array {
  let length = 0;
  for (let i = 0; i < arguments.length; i++) {
    length += arguments[i].length;
  }
  const result = new Uint8Array(length);
  let curOffset = 0;
  for (let i = 0; i < arguments.length; i++) {
    result.set(arguments[i], curOffset);
    curOffset += arguments[i].length;
  }
  return result;
}

/**
 * Converts a hex string to a byte array.
 *
 * @param hex the input
 * @return the byte array output
 * @throws {!InvalidArgumentsException}
 * @static
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 != 0) {
    throw new InvalidArgumentsException(
        'Hex string length must be multiple of 2');
  }
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return arr;
}

/**
 * Converts a byte array to hex.
 *
 * @param bytes the byte array input
 * @return hex the output
 * @static
 */
export function toHex(bytes: Uint8Array): string {
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    const hexByte = bytes[i].toString(16);
    result += hexByte.length > 1 ? hexByte : '0' + hexByte;
  }
  return result;
}
