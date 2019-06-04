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

goog.module('tink.CleartextKeysetHandle');

const BinaryKeysetReader = goog.require('tink.BinaryKeysetReader');
const BinaryKeysetWriter = goog.require('tink.BinaryKeysetWriter');
const KeysetHandle = goog.require('tink.KeysetHandle');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');

/** @type {!BinaryKeysetWriter} */
const binaryKeysetWriter = new BinaryKeysetWriter();

/**
 * Static methods for reading or writing cleartext keysets.
 *
 * @final
 */
class CleartextKeysetHandle {
  /**
   * Creates a KeysetHandle from a JSPB array representation of a keyset. The
   * array is used in place and not cloned.
   *
   * Note that JSPB is currently not open source, so this method can't be
   * either.
   *
   * @param {!Array<*>} keysetJspbArray
   * @return {!KeysetHandle}
   */
  static fromJspbArray(keysetJspbArray) {
    return new KeysetHandle(new PbKeyset(keysetJspbArray));
  }

  /**
   * Creates a KeysetHandle from a JSPB string representation of a keyset.
   *
   * Note that JSPB is currently not open source, so this method can't be
   * either.
   *
   * @param {string} keysetJspbString
   * @return {!KeysetHandle}
   */
  static deserializeFromJspb(keysetJspbString) {
    return new KeysetHandle(PbKeyset.deserialize(keysetJspbString));
  }

  /**
   * Serializes a KeysetHandle to string.
   *
   * Note that JSPB is currently not open source, so this method can't be
   * either.
   *
   * @param {!KeysetHandle} keysetHandle
   * @return {string}
   */
  static serializeToJspb(keysetHandle) {
    return keysetHandle.getKeyset().serialize();
  }

  /**
   * Serializes a KeysetHandle to binary.
   *
   * @param {!KeysetHandle} keysetHandle
   * @return {!Uint8Array}
   */
  static serializeToBinary(keysetHandle) {
    return binaryKeysetWriter.write(keysetHandle.getKeyset());
  }

  /**
   * Creates a KeysetHandle from a binary representation of a keyset.
   *
   * @param {!Uint8Array} keysetBinary
   * @return {!KeysetHandle}
   */
  static deserializeFromBinary(keysetBinary) {
    const reader = BinaryKeysetReader.withUint8Array(keysetBinary);
    const keysetFromReader = reader.read();
    return new KeysetHandle(keysetFromReader);
  }
}

exports = CleartextKeysetHandle;
