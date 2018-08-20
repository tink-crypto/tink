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

goog.module('tink.hybrid.HybridEncryptFactory');

const HybridEncrypt = goog.require('tink.HybridEncrypt');
const HybridEncryptSetWrapper = goog.require('tink.hybrid.HybridEncryptSetWrapper');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const Registry = goog.require('tink.Registry');

/**
 * HybridEncryptFactory allows for obtaining an HybridEncrypt primitive from
 * a KeysetHandle.
 *
 * HybridEncryptFactory gets primitives from the Registry, which can be
 * initialized via a convenience method from HybridConfig class. Here is an
 * example how HybridEncrypt primitive may be obtained and used:
 *
 * HybridConfig.register();
 * const keysetHandle = ...;
 * const hybridEncrypt = await HybridEncryptFactory.getPrimitive(keysetHandle);
 *
 * const plaintext = ...;
 * const hkdfInfo = ...;
 * const ciphertext = await hybridEncrypt.encrypt(plaintext, hkdfInfo);
 *
 * @final
 */
class HybridEncryptFactory {
  /**
   * Returns a HybridEncrypt-primitive that uses key material from the keyset
   * given via keysetHandle. If opt_customKeyManager is defined then the
   * provided key manager is used to instantiate primitives. Otherwise key
   * manager from Registry is used.
   *
   * @param {!KeysetHandle} keysetHandle
   * @param {?KeyManager.KeyManager=} opt_customKeyManager
   *
   * @return {!Promise<!HybridEncrypt>}
   */
  static async getPrimitive(keysetHandle, opt_customKeyManager) {
    const primitives = await Registry.getPrimitives(
        HybridEncrypt, keysetHandle, opt_customKeyManager);
    return HybridEncryptSetWrapper.newHybridEncrypt(primitives);
  }
}

exports = HybridEncryptFactory;
