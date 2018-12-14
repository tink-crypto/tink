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

goog.module('tink.signature.PublicKeySignCatalogue');

const Catalogue = goog.require('tink.Catalogue');
const EcdsaPrivateKeyManager = goog.require('tink.signature.EcdsaPrivateKeyManager');
const KeyManager = goog.require('tink.KeyManager');
const PublicKeySign = goog.require('tink.PublicKeySign');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * A catalogue of TINK key managers for digital signatures.
 *
 * @implements {Catalogue<PublicKeySign>}
 * @final
 */
class PublicKeySignCatalogue {
  /** @override */
  getKeyManager(typeUrl, primitiveName, minVersion) {
    if (primitiveName.toLowerCase() !=
        PublicKeySignCatalogue.SUPPORTED_PRIMITIVE_NAME_.toLowerCase()) {
      throw new SecurityException(
          'Requested ' + primitiveName +
          ' primitive, but this catalogue provides key managers for ' +
          PublicKeySignCatalogue.SUPPORTED_PRIMITIVE_NAME_ + ' primitives.');
    }

    const manager = this.getKeyManagerImpl_(typeUrl);
    if (manager.getVersion() < minVersion) {
      throw new SecurityException(
          'Requested manager with higher version than is available. ' +
          'The available manager has version ' + manager.getVersion()) +
          '.';
    }
    return manager;
  }

  /**
   * @private
   * @param {string} typeUrl
   * @return {!KeyManager.KeyManager}
   */
  getKeyManagerImpl_(typeUrl) {
    let /** !KeyManager.KeyManager */ manager;
    switch (typeUrl) {
      case EcdsaPrivateKeyManager.KEY_TYPE:
        manager = new EcdsaPrivateKeyManager();
        break;
      default:
        throw new SecurityException(
            'There is no key manager for key type ' + typeUrl + ' available.');
    }
    return manager;
  }
}

/** @const @private {string} */
PublicKeySignCatalogue.SUPPORTED_PRIMITIVE_NAME_ = 'PublicKeySign';

exports = PublicKeySignCatalogue;
