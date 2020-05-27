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

const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const {InvalidArgumentsException} = goog.require('google3.third_party.tink.javascript.exception.invalid_arguments_exception');
const KeyManager = goog.require('tink.KeyManager');
const KeysetReader = goog.require('tink.KeysetReader');
const KeysetWriter = goog.require('tink.KeysetWriter');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const Util = goog.require('tink.Util');
const {PbKeyMaterialType, PbKeyStatusType, PbKeyTemplate, PbKeyset} = goog.require('google3.third_party.tink.javascript.internal.proto');

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
    // TODO(thaidn): move this to a key manager.
    const keyset = await KeysetHandle.generateNewKeyset_(keyTemplate);
    return new KeysetHandle(keyset);
  }

  /**
   * Generates a new Keyset that contains a single new key generated
   * according to keyTemplate.
   *
   * @param {!PbKeyTemplate} keyTemplate
   * @private
   * @return {!Promise<!PbKeyset>}
   */
  static async generateNewKeyset_(keyTemplate) {
    const key = new PbKeyset.Key()
                    .setStatus(PbKeyStatusType.ENABLED)
                    .setOutputPrefixType(keyTemplate.getOutputPrefixType());
    const keyId = KeysetHandle.generateNewKeyId_();
    key.setKeyId(keyId);
    const keyData = await Registry.newKeyData(keyTemplate);
    key.setKeyData(keyData);
    const keyset = new PbKeyset();
    keyset.addKey(key);
    keyset.setPrimaryKeyId(keyId);
    return keyset;
  }

  /**
   * Generates a new random key ID.
   *
   * @private
   * @return {number} The key ID.
   */
  static generateNewKeyId_() {
    const bytes = Random.randBytes(4);
    let value = 0;
    for (let i = 0; i < bytes.length; i++) {
      value += (bytes[i] & 0xFF) << (i * 8);
    }
    // Make sure the key ID is a positive integer smaller than 2^32.
    return Math.abs(value) % 2 ** 32;
  };


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
        await this.getPrimitiveSet(primitiveType, opt_customKeyManager);
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
   * @package Visible for testing.
   *
   * @param {!Object} primitiveType
   * @param {?KeyManager.KeyManager<P>=} opt_customKeyManager
   *
   * @return {!Promise.<!PrimitiveSet.PrimitiveSet<P>>}
   */
  async getPrimitiveSet(primitiveType, opt_customKeyManager) {
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
