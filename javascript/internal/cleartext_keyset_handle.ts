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
  static fromJspbArray(keysetJspbArray: AnyDuringMigration[]): KeysetHandle {
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
