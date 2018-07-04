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

goog.module('tink.KeysetHandle');

const Aead = goog.require('tink.Aead');
const KeysetReader = goog.require('tink.KeysetReader');
const KeysetWriter = goog.require('tink.KeysetWriter');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * Keyset handle provide abstracted access to Keysets, to limit the exposure of
 * actual protocol buffers that hold sensitive key material.
 *
 * @final
 */
class KeysetHandle {
  /**
   * Creates a KeysetHandle from an encrypted keyset obtained via reader, using
   * masterKeyAead to decrypt the keyset.
   *
   * @param {!KeysetReader} reader
   * @param {!Aead} masterKeyAead
   *
   * @return {!Promise<!KeysetHandle>}
   */
  async read(reader, masterKeyAead) {
    // TODO implement
    throw new SecurityException('KeysetHandle -- read: Not implemented yet.');
  }

  /**
   * Returns a new KeysetHandle that contains a single new key generated
   * according to keyTemplate.
   *
   * @param {!PbKeyTemplate} keyTemplate
   *
   * @return {!Promise<!KeysetHandle>}
   */
  async generateNew(keyTemplate) {
    // TODO implement
    throw new SecurityException(
        'KeysetHandle -- generateNew: Not implemented yet.');
  }

  /**
   * Encrypts the underlying keyset with the provided masterKeyAead wnd writes
   * the resulting encryptedKeyset to the given writer which must be non-null.
   *
   * @param {!KeysetWriter} writer
   * @param {!Aead} masterKeyAead
   *
   */
  async writeEncrypted(writer, masterKeyAead) {
    // TODO implement
    throw new SecurityException(
        'KeysetHandle -- writeEncrypted: Not implemented yet.');
  }
}

exports = KeysetHandle;
