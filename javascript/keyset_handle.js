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
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const KeyManager = goog.require('tink.KeyManager');
const KeysetReader = goog.require('tink.KeysetReader');
const KeysetWriter = goog.require('tink.KeysetWriter');
const PbKeyMaterialType = goog.require('proto.google.crypto.tink.KeyData.KeyMaterialType');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');
const Util = goog.require('tink.Util');

/**
 * Keyset handle provide abstracted access to Keysets, to limit the exposure of
 * actual protocol buffers that hold sensitive key material.
 *
 * @final
 */
class KeysetHandle {
  /**
   * @param {!PbKeyset} keyset
   */
  constructor(keyset) {
    Util.validateKeyset(keyset);

    /** @const @private {!PbKeyset} */
    this.keyset_ = keyset;
  }

  /**
   * Creates a KeysetHandle from an encrypted keyset obtained via reader, using
   * masterKeyAead to decrypt the keyset.
   *
   * @param {!KeysetReader} reader
   * @param {!Aead} masterKeyAead
   *
   * @return {!Promise<!KeysetHandle>}
   */
  static async read(reader, masterKeyAead) {
    // TODO implement
    throw new SecurityException('KeysetHandle -- read: Not implemented yet.');
  }

  /**
   * Creates a KeysetHandle from a keyset, obtained via reader, which
   * must contain no secret key material.
   *
   * This can be used to load public keysets or envelope encryption keysets.
   * Users that need to load cleartext keysets can use CleartextKeysetHandle.
   *
   * @param {!KeysetReader} reader
   * @return {!KeysetHandle}
   */
  static readNoSecret(reader) {
    if (reader === null) {
      throw new SecurityException('Reader has to be non-null.');
    }
    const keyset = reader.read();
    const keyList = keyset.getKeyList();
    for (let key of keyList) {
      switch (key.getKeyData().getKeyMaterialType()) {
        case PbKeyMaterialType.ASYMMETRIC_PUBLIC:  // fall through
        case PbKeyMaterialType.REMOTE:
          continue;
      }
      throw new SecurityException('Keyset contains secret key material.');
    }
    return new KeysetHandle(keyset);
  }

  /**
   * Returns a new KeysetHandle that contains a single new key generated
   * according to keyTemplate.
   *
   * @param {!PbKeyTemplate} keyTemplate
   *
   * @return {!Promise<!KeysetHandle>}
   */
  static async generateNew(keyTemplate) {
    // TODO implement
    throw new SecurityException(
        'KeysetHandle -- generateNew: Not implemented yet.');
  }

  /**
   * Returns a primitive that uses key material from this keyset handle. If
   * opt_customKeyManager is defined then the provided key manager is used to
   * instantiate primitives. Otherwise key manager from Registry is used.
   *
   * @template P
   *
   * @param {!Object} primitiveType
   * @param {?KeyManager.KeyManager<P>=} opt_customKeyManager
   *
   * @return {!Promise<!P>}
   */
  async getPrimitive(primitiveType, opt_customKeyManager) {
    if (!primitiveType) {
      throw new InvalidArgumentsException('primitive type must be non-null');
    }
    const primitiveSet =
        await this.getPrimitiveSet_(primitiveType, opt_customKeyManager);
    return Registry.wrap(primitiveSet);
  }

  /**
   * Creates a set of primitives corresponding to the keys with status Enabled
   * in the given keysetHandle, assuming all the correspoding key managers are
   * present (keys with status different from Enabled are skipped). If provided
   * uses customKeyManager instead of registered key managers for keys supported
   * by the customKeyManager.
   *
   * @template P
   * @private
   *
   * @param {!Object} primitiveType
   * @param {?KeyManager.KeyManager<P>=} opt_customKeyManager
   *
   * @return {!Promise.<!PrimitiveSet.PrimitiveSet<P>>}
   */
  async getPrimitiveSet_(primitiveType, opt_customKeyManager) {
    const primitiveSet = new PrimitiveSet.PrimitiveSet(primitiveType);
    const keys = this.keyset_.getKeyList();
    const keysLength = keys.length;
    for (let i = 0; i < keysLength; i++) {
      const key = keys[i];
      if (key.getStatus() === PbKeyStatusType.ENABLED) {
        const keyData = key.getKeyData();
        if (!keyData) {
          throw new SecurityException('Key data has to be non null.');
        }
        let primitive;
        if (opt_customKeyManager &&
            opt_customKeyManager.getKeyType() === keyData.getTypeUrl()) {
          primitive =
              await opt_customKeyManager.getPrimitive(primitiveType, keyData);
        } else {
          primitive = await Registry.getPrimitive(primitiveType, keyData);
        }
        const entry = primitiveSet.addPrimitive(primitive, key);
        if (key.getKeyId() === this.keyset_.getPrimaryKeyId()) {
          primitiveSet.setPrimary(entry);
        }
      }
    }
    return primitiveSet;
  }


  /**
   * Encrypts the underlying keyset with the provided masterKeyAead wnd writes
   * the resulting encryptedKeyset to the given writer which must be non-null.
   *
   * @param {!KeysetWriter} writer
   * @param {!Aead} masterKeyAead
   *
   */
  async write(writer, masterKeyAead) {
    // TODO implement
    throw new SecurityException('KeysetHandle -- write: Not implemented yet.');
  }

  /**
   * Returns the keyset held by this KeysetHandle.
   *
   * @package
   * @return {!PbKeyset}
   */
  getKeyset() {
    return this.keyset_;
  }
}

exports = KeysetHandle;
