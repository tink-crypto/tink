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

goog.module('tink.Config');

const Catalogue = goog.require('tink.Catalogue');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const KeyManager = goog.require('tink.KeyManager');
const PbKeyTypeEntry = goog.require('proto.google.crypto.tink.KeyTypeEntry');
const PbRegistryConfig = goog.require('proto.google.crypto.tink.RegistryConfig');
const Registry = goog.require('tink.Registry');

/**
 * Static methods for handling of Tink configurations.
 *
 * Configurations, i.e., a collection of key types and their corresponding key
 * managers supported by a specific run-time environment enable control of Tink
 * setup via JSON-formatted config files that determine which key types are
 * supported, and provide a mechanism for deprecation of obsolete/outdated
 * cryptographic schemes (see tink/proto/config.proto for more info).
 *
 * Example usage:
 *
 * const registryConfig = ...; // create a variable of type PbRegistryConfig
 * Config.register(registryConfig);
 *
 *
 * @final
 */
class Config {
  /**
   * Returns a PbKeyTypeEntry for Tink key types with the specified parameters.
   *
   * @param {string} catalogueName
   * @param {string} primitiveName
   * @param {string} keyProtoName
   * @param {number} keyManagerVersion
   * @param {boolean} newKeyAllowed
   *
   * @return {!PbKeyTypeEntry}
   */
  static getTinkKeyTypeEntry(
      catalogueName, primitiveName, keyProtoName, keyManagerVersion,
      newKeyAllowed) {
    const typeUrl = 'type.googleapis.com/google.crypto.tink.' + keyProtoName;

    const entry = new PbKeyTypeEntry()
                      .setCatalogueName(catalogueName)
                      .setPrimitiveName(primitiveName)
                      .setTypeUrl(typeUrl)
                      .setKeyManagerVersion(keyManagerVersion)
                      .setNewKeyAllowed(newKeyAllowed);

    return entry;
  }

  /**
   * Register key managers for entries determined by config.
   *
   * @param {!PbKeyTypeEntry|!PbRegistryConfig} config
   */
  static register(config) {
    if (!config) {
      throw new InvalidArgumentsException(
          'A non-null KeyTypeEntry or RegistryConfig proto ' +
          'has to be provided.');
    }
    if (config instanceof PbKeyTypeEntry) {
      Config.registerKeyTypeEntry_(config);
    } else {
      const entryList = config.getEntryList();
      for (let entry of entryList) {
        Config.registerKeyTypeEntry_(entry);
      }
    }
  }

  /**
   * Register key manager for an entry.
   *
   * @private
   * @param {!PbKeyTypeEntry} entry
   */
  static registerKeyTypeEntry_(entry) {
    Config.validateKeyTypeEntry_(entry);
    const /** @type {!Catalogue} */ catalogue =
        Registry.getCatalogue(entry.getCatalogueName());
    const /** @type {!KeyManager.KeyManager} */ manager =
        catalogue.getKeyManager(
            entry.getTypeUrl(), entry.getPrimitiveName(),
            entry.getKeyManagerVersion());
    Registry.registerKeyManager(manager, entry.getNewKeyAllowed());
  }

  /**
   * Validates an entry.
   *
   * @private
   * @param {!PbKeyTypeEntry} entry
   */
  static validateKeyTypeEntry_(entry) {
    if (!entry.getTypeUrl()) {
      throw new InvalidArgumentsException(
          'Invalid KeyTypeEntry proto: missing type url.');
    }
    if (!entry.getPrimitiveName()) {
      throw new InvalidArgumentsException(
          'Invalid KeyTypeEntry proto: missing primitive name.');
    }
    if (!entry.getCatalogueName()) {
      throw new InvalidArgumentsException(
          'Invalid KeyTypeEntry proto: missing catalogue name.');
    }
  }
}

exports = Config;
