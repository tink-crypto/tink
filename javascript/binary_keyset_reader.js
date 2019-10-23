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

goog.module('tink.BinaryKeysetReader');

const KeysetReader = goog.require('tink.KeysetReader');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * BinaryKeysetReader knows how to read a keyset or an encrypted keyset
 * serialized to binary format.
 *
 * @implements {KeysetReader}
 * @final
 */
class BinaryKeysetReader {
  /** @param {!Uint8Array} serializedKeyset */
  constructor(serializedKeyset) {
    /** @const @private {!Uint8Array} */
    this.serializedKeyset_ = serializedKeyset;
  }

  /**
   * @param {!Uint8Array} serializedKeyset
   * @return {!BinaryKeysetReader}
   */
  static withUint8Array(serializedKeyset) {
    if (!serializedKeyset) {
      throw new SecurityException('Serialized keyset has to be non-null.');
    }
    return new BinaryKeysetReader(serializedKeyset);
  }

  /** @override */
  read() {
    let /** !PbKeyset */ keyset;
    try {
      keyset = PbKeyset.deserializeBinary(this.serializedKeyset_);
    } catch (e) {
      throw new SecurityException(
          'Could not parse the given serialized proto as a keyset proto.');
    }
    if (keyset.getKeyList().length === 0) {
      throw new SecurityException(
          'Could not parse the given serialized proto as a keyset proto.');
    }
    return keyset;
  }

  /** @override */
  readEncrypted() {
    throw new SecurityException('Not implemented yet.');
  }
}

exports = BinaryKeysetReader;
