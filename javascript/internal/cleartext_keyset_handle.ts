/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {BinaryKeysetReader} from './binary_keyset_reader';
import {BinaryKeysetWriter} from './binary_keyset_writer';
import {KeysetHandle} from './keyset_handle';

const binaryKeysetWriter = new BinaryKeysetWriter();

/**
 * Static methods for reading or writing cleartext keysets.
 *
 * @final
 */
export class CleartextKeysetHandle {
  /**
   * Serializes a KeysetHandle to binary.
   *
   */
  static serializeToBinary(keysetHandle: KeysetHandle): Uint8Array {
    return binaryKeysetWriter.encodeBinary(keysetHandle.getKeyset());
  }

  /**
   * Creates a KeysetHandle from a binary representation of a keyset.
   *
   */
  static deserializeFromBinary(keysetBinary: Uint8Array): KeysetHandle {
    const reader = BinaryKeysetReader.withUint8Array(keysetBinary);
    const keysetFromReader = reader.read();
    return new KeysetHandle(keysetFromReader);
  }
}
