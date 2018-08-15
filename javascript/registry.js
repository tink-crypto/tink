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

const Catalogue = goog.require('tink.Catalogue');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbMessage = goog.require('jspb.Message');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const SecurityException = goog.require('tink.exception.SecurityException');
const Util = goog.require('tink.Util');

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
 * background. Registry is public though to enable configurations with custom
 * catalogues (primitves or KeyManagers).
 *
 * @final
 */
class Registry {
  /**
   * Returns a catalogue with the given name.
   * Throws exception if no catalogue with the given name is found.
   *
   * @template P
   * @static
   *
   * @param {string} catalogueName
   *
   * @return {!Catalogue<P>}
   */
  static getCatalogue(catalogueName) {
    const catalogue = Registry.nameToCatalogueMap_.get(catalogueName);
    if (!catalogue) {
      throw new SecurityException(
          'Catalogue with name ' + catalogueName + ' has not been added.');
    }
    return catalogue;
  }

  /**
   * Adds the given catalogue under the specified catalogueName to enable custom
   * configuration of key types and key managers.
   *
   * Adding a custom catalogue should be a one-time operation and fails if there
   * exists a catalouge with catalogueName.
   *
   * @template P
   * @static
   *
   * @param {string} catalogueName
   * @param {!Catalogue<P>} catalogue
   */
  // This function could be async and there would be no problem with concurency
  // as it does not use await at all. But without async it is more consistent
  // with Java version.
  static addCatalogue(catalogueName, catalogue) {
    if (!catalogueName) {
      throw new SecurityException('Catalogue must have name.');
    }
    if (!catalogue) {
      throw new SecurityException('Catalogue cannot be null.');
    }
    if (Registry.nameToCatalogueMap_.has(catalogueName)) {
      throw new SecurityException('Catalogue name already exists.');
    }
    Registry.nameToCatalogueMap_.set(catalogueName, catalogue);
  }


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
        throw new SecurityException('Key manager for key type ' + typeUrl +
            ' has already been registered and cannot be overwritten.');
      }

      // It is forbidden to change new_key_allowed from false to true.
      if (!(Registry.typeToNewKeyAllowedMap_.get(typeUrl)) &&
          opt_newKeyAllowed) {
        throw new SecurityException('Key manager for key type ' + typeUrl +
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

    const manager = await Registry.getKeyManager(opt_typeUrl);
    return manager.getPrimitive(primitiveType, key);
  }

  /**
   * Creates a set of primitives corresponding to the keys with status Enabled
   * in the given keysetHandle, assuming all the correspoding key managers are
   * present (keys with status different from Enabled are skipped). If provided
   * uses customKeyManager instead of registered key managers for keys supported
   * by the customKeyManager.
   *
   * @template P
   * @static
   *
   * @param {!Object} primitiveType
   * @param {!KeysetHandle} keysetHandle
   * @param {KeyManager.KeyManager<P>=} opt_customKeyManager
   *
   * @return {!Promise.<!PrimitiveSet.PrimitiveSet<P>>}
   */
  static async getPrimitives(
      primitiveType, keysetHandle, opt_customKeyManager) {
    if (!keysetHandle) {
      throw new SecurityException('Keyset handle has to be non-null.');
    }
    Util.validateKeyset(keysetHandle.getKeyset());
    const primitives = new PrimitiveSet.PrimitiveSet();

    const keys = keysetHandle.getKeyset().getKeyList();
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
        const entry = await primitives.addPrimitive(primitive, key);
        if (key.getKeyId() === keysetHandle.getKeyset().getPrimaryKeyId()) {
          await primitives.setPrimary(entry);
        }
      }
    }
    return primitives;
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
   * Resets the registry.
   * After reset the registry is empty, i.e. it contains neither catalogues
   * nor key managers.
   *
   * This method is only for testing.
   *
   * @static
   */
  static reset() {
    Registry.typeToManagerMap_.clear();
    Registry.typeToNewKeyAllowedMap_.clear();
    Registry.nameToCatalogueMap_.clear();
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
}
// key managers maps
/**
 * @static @private {Map<string,KeyManager.KeyManager>}
 *
 */
Registry.typeToManagerMap_ = new Map();
/**
 * @static @private {Map<string,boolean>}
 */
Registry.typeToNewKeyAllowedMap_ = new Map();

// catalogues maps
/**
 * @static @private {Map<string,Catalogue>}
 */
Registry.nameToCatalogueMap_ = new Map();

exports = Registry;
