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

goog.module('tink.Registry');

const KeyManager = goog.require('tink.KeyManager');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbMessage = goog.require('jspb.Message');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PrimitiveWrapper = goog.require('tink.PrimitiveWrapper');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * Registry for KeyManagers.
 *
 * Registry maps supported key types to corresponding KeyManager objects (i.e.
 * the KeyManagers which may instantiate the primitive corresponding to the
 * given key or generate new key of the given type). Keeping KeyManagers for all
 * primitives in a single Registry (rather than having a separate keyManager per
 * primitive) enables modular construction of compound primitives from "simple"
 * ones (e.g. AES-CTR-HMAC AEAD encryption from IND-CPA encryption and MAC).
 *
 * Regular users will not usually work with Registry directly, but via primitive
 * factories, which query Registry for the specific KeyManagers in the
 * background.
 *
 * @final
 */
class Registry {
  /**
   * Register the given manager for the given key type. Manager must be
   * non-nullptr. New keys are allowed if not specified.
   *
   * @template P
   * @static
   *
   * @param {!KeyManager.KeyManager<P>} manager
   * @param {boolean=} opt_newKeyAllowed
   */
  static registerKeyManager(manager, opt_newKeyAllowed) {
    if (opt_newKeyAllowed === undefined) {
      opt_newKeyAllowed = true;
    }
    if (!manager) {
      throw new SecurityException('Key manager cannot be null.');
    }
    const typeUrl = manager.getKeyType();

    if (Registry.typeToManagerMap_.has(typeUrl)) {
      // Cannot overwrite the existing key manager by a new one.
      if (!(Registry.typeToManagerMap_.get(typeUrl) instanceof
            manager.constructor)) {
        throw new SecurityException(
            'Key manager for key type ' + typeUrl +
            ' has already been registered and cannot be overwritten.');
      }

      // It is forbidden to change new_key_allowed from false to true.
      if (!(Registry.typeToNewKeyAllowedMap_.get(typeUrl)) &&
          opt_newKeyAllowed) {
        throw new SecurityException(
            'Key manager for key type ' + typeUrl +
            ' has already been registered with forbidden new key operation.');
      }
      Registry.typeToNewKeyAllowedMap_.set(typeUrl, opt_newKeyAllowed);
    }

    Registry.typeToManagerMap_.set(typeUrl, manager);
    Registry.typeToNewKeyAllowedMap_.set(typeUrl, opt_newKeyAllowed);
  }

  /**
   * Returns a key manager for the given key type or throws an exception if no
   * such manager found.
   *
   * @template P
   * @static
   *
   * @param {string} typeUrl -- key type
   *
   * @return {!KeyManager.KeyManager<P>}
   */
  static getKeyManager(typeUrl) {
    const res = Registry.typeToManagerMap_.get(typeUrl);
    if (!res) {
      throw new SecurityException(
          'Key manager for key type ' + typeUrl + ' has not been registered.');
    }
    return res;
  }

  /**
   * It finds KeyManager according to key type (which is either given by
   * PbKeyData or given by opt_typeUrl), than calls the corresponding
   * manager's getPrimitive method.
   *
   * Either key is of type PbKeyData or opt_typeUrl must be provided.
   *
   * @template P
   * @static
   *
   * @param {!Object} primitiveType
   * @param {!PbKeyData|!PbMessage} key -- key is either a proto of some key
   *     or key data.
   * @param {?string=} opt_typeUrl -- key type
   *
   * @return {!Promise.<!P>}
   */
  static async getPrimitive(primitiveType, key, opt_typeUrl) {
    if (key instanceof PbKeyData) {
      if (opt_typeUrl && key.getTypeUrl() != opt_typeUrl) {
        throw new SecurityException(
            'Key type is ' + opt_typeUrl + ', but it is expected to be ' +
            key.getTypeUrl() + ' or undefined.');
      }
      opt_typeUrl = key.getTypeUrl();
    }

    if (!opt_typeUrl) {
      throw new SecurityException('Key type has to be specified.');
    }

    const manager = Registry.getKeyManager(opt_typeUrl);
    return await manager.getPrimitive(primitiveType, key);
  }

  /**
   * Generates a new PbKeyData for the specified keyTemplate. It finds a
   * KeyManager given by keyTemplate.typeUrl and calls the newKeyData method of
   * that manager.
   *
   * @static
   *
   * @param {!PbKeyTemplate} keyTemplate
   *
   * @return {!Promise<!PbKeyData>}
   */
  static async newKeyData(keyTemplate) {
    const manager = Registry.getKeyManagerWithNewKeyAllowedCheck_(keyTemplate);
    return await manager.getKeyFactory().newKeyData(
        keyTemplate.getValue_asU8());
  }

  /**
   * Generates a new key for the specified keyTemplate using the
   * KeyManager determined by typeUrl field of the keyTemplate.
   *
   * @static
   *
   * @param {!PbKeyTemplate} keyTemplate
   *
   * @return {!Promise<!PbMessage>} returns a key proto
   */
  static async newKey(keyTemplate) {
    const manager = Registry.getKeyManagerWithNewKeyAllowedCheck_(keyTemplate);
    return await manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  }

  /**
   * Convenience method for extracting the public key data from the private key
   * given by serializedPrivateKey.
   * It looks up a KeyManager identified by typeUrl, which must hold
   * PrivateKeyFactory, and calls getPublicKeyData method of that factory.
   *
   * @param {string} typeUrl
   * @param {!Uint8Array} serializedPrivateKey
   * @return {!PbKeyData}
   */
  static getPublicKeyData(typeUrl, serializedPrivateKey) {
    const manager = Registry.getKeyManager(typeUrl);
    // This solution might cause some problems in the future due to Closure
    // compiler optimizations, which may map factory.getPublicKeyData to
    // concrete function.
    const factory = /** @type{?} */ (manager.getKeyFactory());
    if (!factory.getPublicKeyData) {
      throw new SecurityException(
          'Key manager for key type ' + typeUrl +
          ' does not have a private key factory.');
    }
    return factory.getPublicKeyData(serializedPrivateKey);
  }

  /**
   * Resets the registry.
   * After reset the registry is empty, i.e. it contains no key managers.
   *
   * This method is only for testing.
   *
   * @static
   */
  static reset() {
    Registry.typeToManagerMap_.clear();
    Registry.typeToNewKeyAllowedMap_.clear();
    Registry.primitiveTypeToWrapper_.clear();
  }

  /**
   * It finds a KeyManager given by keyTemplate.typeUrl and returns it if it
   * allows creating new keys.
   *
   * @private
   * @param {!PbKeyTemplate} keyTemplate
   *
   * @return {!KeyManager.KeyManager}
   */
  static getKeyManagerWithNewKeyAllowedCheck_(keyTemplate) {
    const keyType = keyTemplate.getTypeUrl();
    const manager = Registry.getKeyManager(keyType);
    if (!Registry.typeToNewKeyAllowedMap_.get(keyType)) {
      throw new SecurityException(
          'New key operation is forbidden for ' +
          'key type: ' + keyType + '.');
    }

    return manager;
  }

  /**
   * Tries to register a primitive wrapper.
   *
   * @template P
   * @static
   *
   * @param {!PrimitiveWrapper<P>} wrapper
   */
  static registerPrimitiveWrapper(wrapper) {
    if (!wrapper) {
      throw new SecurityException('primitive wrapper cannot be null');
    }
    const primitiveType = wrapper.getPrimitiveType();
    if (!primitiveType) {
      throw new SecurityException('primitive wrapper cannot be undefined');
    }

    if (Registry.primitiveTypeToWrapper_.has(primitiveType)) {
      // Cannot overwrite the existing key manager by a new one.
      if (!(Registry.primitiveTypeToWrapper_.get(primitiveType) instanceof
            wrapper.constructor)) {
        throw new SecurityException(
            'primitive wrapper for type ' + primitiveType +
            ' has already been registered and cannot be overwritten');
      }
    }

    Registry.primitiveTypeToWrapper_.set(primitiveType, wrapper);
  }

  /**
   * Wraps a PrimitiveSet and returns a single instance.
   *
   * @template P
   * @static
   *
   * @param {!PrimitiveSet.PrimitiveSet<P>} primitiveSet
   * @return {!P}
   */
  static wrap(primitiveSet) {
    if (!primitiveSet) {
      throw new SecurityException('primitive set cannot be null.');
    }
    const primitiveType = primitiveSet.getPrimitiveType();
    const wrapper = Registry.primitiveTypeToWrapper_.get(primitiveType);
    if (!wrapper) {
      throw new SecurityException(
          'no primitive wrapper found for type ' + primitiveType);
    }
    return wrapper.wrap(primitiveSet);
  }
}
// key managers maps
/**
 * @static @private {!Map<string,!KeyManager.KeyManager>}
 *
 */
Registry.typeToManagerMap_ = new Map();
/**
 * @static @private {!Map<string,boolean>}
 */
Registry.typeToNewKeyAllowedMap_ = new Map();

// primitive wrappers map
/**
 * @static @private {!Map<!Object,!PrimitiveWrapper>}
 */
Registry.primitiveTypeToWrapper_ = new Map();

exports = Registry;
