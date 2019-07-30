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

goog.module('tink.hybrid.HybridConfig');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const Config = goog.require('tink.Config');
const EciesAeadHkdfPrivateKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPrivateKeyManager');
const EciesAeadHkdfPublicKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPublicKeyManager');
const HybridDecryptCatalogue = goog.require('tink.hybrid.HybridDecryptCatalogue');
const HybridDecryptWrapper = goog.require('tink.hybrid.HybridDecryptWrapper');
const HybridEncryptCatalogue = goog.require('tink.hybrid.HybridEncryptCatalogue');
const HybridEncryptWrapper = goog.require('tink.hybrid.HybridEncryptWrapper');
const PbKeyTypeEntry = goog.require('proto.google.crypto.tink.KeyTypeEntry');
const PbRegistryConfig = goog.require('proto.google.crypto.tink.RegistryConfig');
const Registry = goog.require('tink.Registry');

// Static methods and constants for registering with the Registry all instances
// of key types for hybrid encryption and decryption supported in a particular
// release of Tink.
//
// To register all key types from the current Tink release one can do:
//
// HybridConfig.register();
//
// For more information on creation and usage of hybrid encryption instances
// see HybridEncryptFactory (for encryption) and HybridDecryptFactory (for
// decryption).

/**
 * Returns config of hybrid encryption and decryption implementations
 * supported by the current Tink release.
 *
 * @return {!PbRegistryConfig}
 */
const latest = function() {
  const config = new PbRegistryConfig().setConfigName(CONFIG_NAME_);

  config.addEntry(createEntry_(
      ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE, /* keyManagerVersion = */ 0,
      ENCRYPT_PRIMITIVE_NAME, ENCRYPT_CATALOGUE_NAME));
  config.addEntry(createEntry_(
      ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE, /* keyManagerVersion = */ 0,
      DECRYPT_PRIMITIVE_NAME, DECRYPT_CATALOGUE_NAME));
  return config;
};

/**
 * Registers key managers for all HybridEncrypt and HybridDecrypt key types
 * from the current Tink release.
 */
const register = function() {
  AeadConfig.register();
  Registry.addCatalogue(ENCRYPT_CATALOGUE_NAME, new HybridEncryptCatalogue());
  Registry.registerPrimitiveWrapper(new HybridEncryptWrapper());
  Registry.addCatalogue(DECRYPT_CATALOGUE_NAME, new HybridDecryptCatalogue());
  Registry.registerPrimitiveWrapper(new HybridDecryptWrapper());
  Config.register(latest());
};

/**
 * Creates KeyTypeEntry with the given parameters.
 *
 * @param {string} typeUrl
 * @param {number} keyManagerVersion
 * @param {string} primitiveName
 * @param {string} catalogueName
 * @param {boolean=} opt_newKeyAllowed (default: true)
 *
 * @return {!PbKeyTypeEntry}
 * @private
 */
const createEntry_ = function(
    typeUrl, keyManagerVersion, primitiveName, catalogueName,
    opt_newKeyAllowed = true) {
  const entry = new PbKeyTypeEntry()
                    .setPrimitiveName(primitiveName)
                    .setTypeUrl(typeUrl)
                    .setKeyManagerVersion(keyManagerVersion)
                    .setNewKeyAllowed(opt_newKeyAllowed)
                    .setCatalogueName(catalogueName);

  return entry;
};

/** @const @private {string} */
const CONFIG_NAME_ = 'TINK_HYBRID';

/** @const {string} */
const ENCRYPT_CATALOGUE_NAME = 'TinkHybridEncrypt';
/** @const {string} */
const ENCRYPT_PRIMITIVE_NAME = 'HybridEncrypt';
/** @const {string} */
const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE = EciesAeadHkdfPublicKeyManager.KEY_TYPE;

/** @const {string} */
const DECRYPT_CATALOGUE_NAME = 'TinkHybridDecrypt';
/** @const {string} */
const DECRYPT_PRIMITIVE_NAME = 'HybridDecrypt';
/** @const {string} */
const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE =
    EciesAeadHkdfPrivateKeyManager.KEY_TYPE;

exports = {
  latest,
  register,
  ENCRYPT_CATALOGUE_NAME,
  ENCRYPT_PRIMITIVE_NAME,
  ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE,
  DECRYPT_CATALOGUE_NAME,
  DECRYPT_PRIMITIVE_NAME,
  ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE,
};
