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

const EcdsaPrivateKeyManager = goog.require('tink.signature.EcdsaPrivateKeyManager');
const EcdsaPublicKeyManager = goog.require('tink.signature.EcdsaPublicKeyManager');
const PublicKeySignWrapper = goog.require('tink.signature.PublicKeySignWrapper');
const PublicKeyVerifyWrapper = goog.require('tink.signature.PublicKeyVerifyWrapper');
const Registry = goog.require('google3.third_party.tink.javascript.internal.registry');

// Static methods and constants for registering with the Registry all instances
// of key types for digital signature supported in a particular release of Tink.
//
// To register all key types from the current Tink release one can do:
//
// SignatureConfig.register();
//

/**
 * Registers key managers for all PublicKeyVerify and PublicKeySign key types
 * from the current Tink release.
 */
const register = function() {
  Registry.registerKeyManager(new EcdsaPrivateKeyManager());
  Registry.registerKeyManager(new EcdsaPublicKeyManager());
  Registry.registerPrimitiveWrapper(new PublicKeySignWrapper());
  Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
};

/** @const {string} */
const VERIFY_PRIMITIVE_NAME = 'PublicKeyVerify';
/** @const {string} */
const ECDSA_PUBLIC_KEY_TYPE = EcdsaPublicKeyManager.KEY_TYPE;

/** @const {string} */
const SIGN_PRIMITIVE_NAME = 'PublicKeySign';
/** @const {string} */
const ECDSA_PRIVATE_KEY_TYPE = EcdsaPrivateKeyManager.KEY_TYPE;

exports = {
  register,
  VERIFY_PRIMITIVE_NAME,
  ECDSA_PUBLIC_KEY_TYPE,
  SIGN_PRIMITIVE_NAME,
  ECDSA_PRIVATE_KEY_TYPE,
};
