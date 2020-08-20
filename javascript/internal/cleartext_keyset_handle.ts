/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {BinaryKeysetReader} from './binary_keyset_reader';
import {BinaryKeysetWriter} from './binary_keyset_writer';
import {KeysetHandle} from './keyset_handle';
import {PbKeyset} from './proto';

const binaryKeysetWriter = new BinaryKeysetWriter();

/**
 * Static methods for reading or writing cleartext keysets.
 *
 * @final
 */
export class CleartextKeysetHandle {
  /**
   * Creates a KeysetHandle from a JSPB array representation of a keyset. The
   * array is used in place and not cloned.
   *
   * Note that JSPB is currently not open source, so this method can't be
   * either.
   *
   */
  static fromJspbArray(keysetJspbArray: unknown[]): KeysetHandle {
    return new KeysetHandle(new PbKeyset(keysetJspbArray));
  }

  /**
   * Creates a KeysetHandle from a JSPB string representation of a keyset.
   *
   * Note that JSPB is currently not open source, so this method can't be
   * either.
   *
   */
  static deserializeFromJspb(keysetJspbString: string): KeysetHandle {
    return new KeysetHandle(PbKeyset.deserialize(keysetJspbString));
  }

  /**
   * Serializes a KeysetHandle to string.
   *
   * Note that JSPB is currently not open source, so this method can't be
   * either.
   *
   */
  static serializeToJspb(keysetHandle: KeysetHandle): string {
    return keysetHandle.getKeyset().serialize();
  }

  /**
   * Serializes a KeysetHandle to binary.
   *
   */
  static serializeToBinary(keysetHandle: KeysetHandle): Uint8Array {
    return binaryKeysetWriter.write(keysetHandle.getKeyset());
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
