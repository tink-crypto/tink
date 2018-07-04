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
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbMessage = goog.require('jspb.Message');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
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
   * @return {!Promise.<!Catalogue<P>>}
   */
  static async getCatalogue(catalogueName) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
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
  static async addCatalogue(catalogueName, catalogue) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
  }

  /**
   * Register the given manager for the given key type. Manager must be
   * non-nullptr. New keys are allowed if not specified.
   *
   * @template P
   * @static
   *
   * @param {string} typeUrl -- key type
   * @param {!KeyManager.KeyManager<P>} manager
   * @param {?boolean=} opt_newKeyAllowed
   */
  static async registerKeyManager(typeUrl, manager, opt_newKeyAllowed = true) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
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
   * @return {!Promise.<!KeyManager.KeyManager<P>>}
   */
  static async getKeyManager(typeUrl) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
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
   * @param {!PbKeyData|!PbMessage|Uint8Array} key -- key is either a
   *     (serialized) proto of some key or key data.
   * @param {?string=} opt_typeUrl -- key type
   *
   * @return {!Promise.<!KeyManager.KeyManager<P>>}
   */
  static async getPrimitive(key, opt_typeUrl) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
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
   * @param {!KeysetHandle} keysetHandle
   * @param {KeyManager.KeyManager<P>=} opt_customKeyManager
   *
   * @return {!Promise.<!PrimitiveSet.PrimitiveSet<P>>}
   */
  static async getPrimitives(keysetHandle, opt_customKeyManager) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
  }

  /**
   * Generates a new key for specified keyDescription, which is either
   * KeyTemplate proto or key format proto for some key.
   *
   * If keyDescription is key format proto, opt_typeUrl has to be provided
   *
   * @static
   *
   * @param {!PbKeyTemplate|!PbMessage} keyDescription
   * @param {?string=} opt_typeUrl
   *
   * @return {!Promise.<!PbMessage>}
   */
  static async newKey(keyDescription, opt_typeUrl) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
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
   * @return {!Promise.<!PbKeyData>}
   */
  static async newKeyData(keyTemplate) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
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
  static async reset() {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
  }

  /**
   * Returns a KeyFactory handling the given keyType.
   *
   * @static
   * @private
   *
   * @param {string} keyType
   *
   * @return {!Promise.<!KeyManager.KeyFactory>}
   */
  static async getKeyFactory_(keyType) {
    // TODO implement
    throw new SecurityException('Not implemented yet.');
  }
}

exports = Registry;
