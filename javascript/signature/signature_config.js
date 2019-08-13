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

goog.module('tink.signature.SignatureConfig');

const Config = goog.require('tink.Config');
const EcdsaPrivateKeyManager = goog.require('tink.signature.EcdsaPrivateKeyManager');
const EcdsaPublicKeyManager = goog.require('tink.signature.EcdsaPublicKeyManager');
const PbKeyTypeEntry = goog.require('proto.google.crypto.tink.KeyTypeEntry');
const PbRegistryConfig = goog.require('proto.google.crypto.tink.RegistryConfig');
const PublicKeySignCatalogue = goog.require('tink.signature.PublicKeySignCatalogue');
const PublicKeySignWrapper = goog.require('tink.signature.PublicKeySignWrapper');
const PublicKeyVerifyCatalogue = goog.require('tink.signature.PublicKeyVerifyCatalogue');
const PublicKeyVerifyWrapper = goog.require('tink.signature.PublicKeyVerifyWrapper');
const Registry = goog.require('tink.Registry');

// Static methods and constants for registering with the Registry all instances
// of key types for digital signature supported in a particular release of Tink.
//
// To register all key types from the current Tink release one can do:
//
// SignatureConfig.register();
//

/**
 * Returns config of digital signature implementations
 * supported by the current Tink release.
 *
 * @return {!PbRegistryConfig}
 */
const latest = function() {
  const config = new PbRegistryConfig().setConfigName(CONFIG_NAME_);

  config.addEntry(createEntry_(
      ECDSA_PUBLIC_KEY_TYPE, /* keyManagerVersion = */ 0, VERIFY_PRIMITIVE_NAME,
      VERIFY_CATALOGUE_NAME));
  config.addEntry(createEntry_(
      ECDSA_PRIVATE_KEY_TYPE, /* keyManagerVersion = */ 0, SIGN_PRIMITIVE_NAME,
      SIGN_CATALOGUE_NAME));
  return config;
};

/**
 * Registers key managers for all PublicKeyVerify and PublicKeySign key types
 * from the current Tink release.
 */
const register = function() {
  Registry.addCatalogue(VERIFY_CATALOGUE_NAME, new PublicKeyVerifyCatalogue());
  Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
  Registry.addCatalogue(SIGN_CATALOGUE_NAME, new PublicKeySignCatalogue());
  Registry.registerPrimitiveWrapper(new PublicKeySignWrapper());
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
const CONFIG_NAME_ = 'TINK_SIGNATURE';

/** @const {string} */
const VERIFY_CATALOGUE_NAME = 'TinkPublicKeyVerify';
/** @const {string} */
const VERIFY_PRIMITIVE_NAME = 'PublicKeyVerify';
/** @const {string} */
const ECDSA_PUBLIC_KEY_TYPE = EcdsaPublicKeyManager.KEY_TYPE;

/** @const {string} */
const SIGN_CATALOGUE_NAME = 'TinkPublicKeySign';
/** @const {string} */
const SIGN_PRIMITIVE_NAME = 'PublicKeySign';
/** @const {string} */
const ECDSA_PRIVATE_KEY_TYPE = EcdsaPrivateKeyManager.KEY_TYPE;

exports = {
  latest,
  register,
  VERIFY_CATALOGUE_NAME,
  VERIFY_PRIMITIVE_NAME,
  ECDSA_PUBLIC_KEY_TYPE,
  SIGN_CATALOGUE_NAME,
  SIGN_PRIMITIVE_NAME,
  ECDSA_PRIVATE_KEY_TYPE,
};
