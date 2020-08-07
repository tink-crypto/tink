/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * @fileoverview Several simple wrappers of crypto.getRandomValues.
 */
import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';

/**
 * Randomly generates `n` bytes.
 *
 * @param n number of bytes to generate
 * @return the random bytes
 * @static
 */
export function randBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) {
    throw new InvalidArgumentsException('n must be a nonnegative integer');
  }
  const result = new Uint8Array(n);
  crypto.getRandomValues(result);
  return result;
}
