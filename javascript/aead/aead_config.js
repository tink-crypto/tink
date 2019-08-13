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

goog.module('tink.aead.AeadConfig');

const AeadCatalogue = goog.require('tink.aead.AeadCatalogue');
const AeadWrapper = goog.require('tink.aead.AeadWrapper');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');
const Config = goog.require('tink.Config');
const PbKeyTypeEntry = goog.require('proto.google.crypto.tink.KeyTypeEntry');
const PbRegistryConfig = goog.require('proto.google.crypto.tink.RegistryConfig');
const Registry = goog.require('tink.Registry');


/**
 * Static methods and constants for registering with the Registry all instances
 * of Aead key types supported in a particular release of Tink.
 *
 * To register all Aead key types from the current Tink release one can do:
 *
 * AeadConfig.register();
 *
 * For more information on creation and usage of Aead instances see AeadFactory.
 *
 * @final
 */
class AeadConfig {
  /**
   * Returns config of Aead implementations supported in the current Tink
   * release.
   *
   * @return {!PbRegistryConfig}
   */
  static latest() {
    const config =
        new PbRegistryConfig().setConfigName(AeadConfig.CONFIG_NAME_);

    config.addEntry(AeadConfig.createEntry_(
        AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL, /* keyManagerVersion = */ 0));

    config.addEntry(AeadConfig.createEntry_(
        AeadConfig.AES_GCM_TYPE_URL, /* keyManagerVersion = */ 0));

    return config;
  }

  /**
   * Registers key managers for all Aead key types from the current Tink
   * release.
   */
  static register() {
    // TODO MacConfig.register() should be here.
    Registry.addCatalogue(AeadConfig.CATALOGUE_NAME, new AeadCatalogue());
    Registry.registerPrimitiveWrapper(new AeadWrapper());
    Config.register(AeadConfig.latest());
  }

  /**
   * Creates KeyTypeEntry for the given parameters. The primitiveName and
   * catalogueName are set according to correspoding AeadConfig variables.
   *
   * @param {string} typeUrl
   * @param {number} keyManagerVersion
   * @param {boolean=} opt_newKeyAllowed
   *
   * @return {!PbKeyTypeEntry}
   * @private
   */
  static createEntry_(typeUrl, keyManagerVersion, opt_newKeyAllowed = true) {
    const entry = new PbKeyTypeEntry()
                      .setPrimitiveName(AeadConfig.PRIMITIVE_NAME)
                      .setTypeUrl(typeUrl)
                      .setKeyManagerVersion(keyManagerVersion)
                      .setNewKeyAllowed(opt_newKeyAllowed)
                      .setCatalogueName(AeadConfig.CATALOGUE_NAME);

    return entry;
  }
}

/** @const @private {string} */
AeadConfig.CONFIG_NAME_ = 'TINK_AEAD';
/** @const {string} */
AeadConfig.CATALOGUE_NAME = 'TinkAead';
/** @const {string} */
AeadConfig.PRIMITIVE_NAME = 'Aead';

/** @const {string} */
AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL = AesCtrHmacAeadKeyManager.KEY_TYPE;

/** @const {string} */
AeadConfig.AES_GCM_TYPE_URL = AesGcmKeyManager.KEY_TYPE;

exports = AeadConfig;
