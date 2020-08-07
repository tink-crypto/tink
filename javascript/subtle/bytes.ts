/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';

/**
 * Does near constant time byte array comparison.
 * @param ba1 The first bytearray to check.
 * @param ba2 The second bytearray to check.
 * @return If the array are equal.
 */
export function isEqual(ba1: Uint8Array, ba2: Uint8Array): boolean {
  if (ba1.length !== ba2.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < ba1.length; i++) {
    result |= ba1[i] ^ ba2[i];
  }
  return result == 0;
}

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
 * Converts a non-negative integer number to a 64-bit big-endian byte array.
 * @param value The number to convert.
 * @return The number as a big-endian byte array.
 * @throws {InvalidArgumentsException}
 * @static
 */
export function fromNumber(value: number): Uint8Array {
  if (Number.isNaN(value) || value % 1 !== 0) {
    throw new InvalidArgumentsException('cannot convert non-integer value');
  }
  if (value < 0) {
    throw new InvalidArgumentsException('cannot convert negative number');
  }
  if (value > Number.MAX_SAFE_INTEGER) {
    throw new InvalidArgumentsException(
        'cannot convert number larger than ' + Number.MAX_SAFE_INTEGER);
  }
  const twoPower32 = 2 ** 32;
  let low = value % twoPower32;
  let high = value / twoPower32;
  const result = new Uint8Array(8);
  for (let i = 7; i >= 4; i--) {
    result[i] = low & 255;
    low >>>= 8;
  }
  for (let i = 3; i >= 0; i--) {
    result[i] = high & 255;
    high >>>= 8;
  }
  return result;
}

/**
 * Converts the hex string to a byte array.
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

/**
 * Converts the Base64 string to a byte array.
 *
 * @param encoded the base64 string
 * @param opt_webSafe True indicates we should use the alternative
 *     alphabet, which does not require escaping for use in URLs.
 * @return the byte array output
 * @static
 */
export function fromBase64(encoded: string, opt_webSafe?: boolean): Uint8Array {
  if (opt_webSafe) {
    const normalBase64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
    return fromByteString(window.atob(normalBase64));
  }
  return fromByteString(window.atob(encoded));
}

/**
 * Base64 encode a byte array.
 *
 * @param bytes the byte array input
 * @param opt_webSafe True indicates we should use the alternative
 *     alphabet, which does not require escaping for use in URLs.
 * @return base64 output
 * @static
 */
export function toBase64(bytes: Uint8Array, opt_webSafe?: boolean): string {
  const encoded = window
                      .btoa(
                          /* padding */
                          toByteString(bytes))
                      .replace(/=/g, '');
  if (opt_webSafe) {
    return encoded.replace(/\+/g, '-').replace(/\//g, '_');
  }
  return encoded;
}

/**
 * Converts a byte string to a byte array. Only support ASCII and Latin-1
 * strings, does not support multi-byte characters.
 *
 * @param str the input
 * @return the byte array output
 * @static
 */
export function fromByteString(str: string): Uint8Array {
  const output = [];
  let p = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    output[p++] = c;
  }
  return new Uint8Array(output);
}

/**
 * Turns a byte array into the string given by the concatenation of the
 * characters to which the numbers correspond. Each byte is corresponding to a
 * character. Does not support multi-byte characters.
 *
 * @param bytes Array of numbers representing
 *     characters.
 * @return Stringification of the array.
 */
export function toByteString(bytes: Uint8Array): string {
  let str = '';
  for (let i = 0; i < bytes.length; i += 1) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}
