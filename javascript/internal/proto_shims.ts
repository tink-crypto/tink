/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @fileoverview A set of helper functions to deal with deltas between the 1P
 * and 3P proto APIs.
 *
 * This is the open source version.
 */

import {fromBase64} from '../subtle/bytes';

/** Transforms the bytes field value to a Uint8Array. */
export function bytesAsU8(b: string|Uint8Array): Uint8Array;
export function bytesAsU8(b: string|Uint8Array|undefined): Uint8Array|undefined;
export function bytesAsU8(b: string|Uint8Array|undefined): Uint8Array|
    undefined {
  if (b == null) {
    return undefined;
  }
  if (typeof b === 'string') {
    return fromBase64(b, true);
  }
  return b as Uint8Array;
}

/** Returns the length of the bytes field. */
export function bytesLength(b: string|Uint8Array): number;
export function bytesLength(b: string|Uint8Array|undefined): number|undefined;
export function bytesLength(b: string|Uint8Array|undefined): number|undefined {
  if (b == null) {
    return undefined;
  }
  if (typeof b === 'string') {
    return fromBase64(b, true).length;
  }
  return (b as Uint8Array).length;
}

/** A type union representing a serialized proto */
export type ProtoBytes = string|Uint8Array;
