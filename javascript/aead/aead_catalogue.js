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

goog.module('tink.aead.AeadCatalogue');

const Aead = goog.require('tink.Aead');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');
const Catalogue = goog.require('tink.Catalogue');
const KeyManager = goog.require('tink.KeyManager');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * A catalogue of TINK Aead key managers.
 *
 * @implements {Catalogue<Aead>}
 * @final
 */
class AeadCatalogue {
  /**
   * @override
   */
  getKeyManager(typeUrl, primitiveName, minVersion) {
    if (primitiveName.toLowerCase() !=
        AeadCatalogue.SUPPORTED_PRIMITIVE_NAME_.toLowerCase()) {
      throw new SecurityException(
          'Requested ' + primitiveName +
          ' primitive, but this catalogue provides key managers for ' +
          AeadCatalogue.SUPPORTED_PRIMITIVE_NAME_ + ' primitives.');
    }

    let /** !KeyManager.KeyManager */ manager;
    switch (typeUrl) {
      case AesCtrHmacAeadKeyManager.KEY_TYPE:
        manager = new AesCtrHmacAeadKeyManager();
        break;
      case AesGcmKeyManager.KEY_TYPE:
        manager = new AesGcmKeyManager();
        break;
      default:
        throw new SecurityException(
            'There is no key manager for key type: ' + typeUrl + '.');
    }

    if (manager.getVersion() < minVersion) {
      throw new SecurityException(
          'Requested manager with higher version than is available. ' +
          'The available manager has version ' + manager.getVersion()) +
          '.';
    }
    return manager;
  }
}

/** @const @private {string} */
AeadCatalogue.SUPPORTED_PRIMITIVE_NAME_ = 'Aead';

exports = AeadCatalogue;
