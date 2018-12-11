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

goog.module('tink.hybrid.HybridDecryptFactory');

const HybridDecrypt = goog.require('tink.HybridDecrypt');
const HybridDecryptWrapper = goog.require('tink.hybrid.HybridDecryptWrapper');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const Registry = goog.require('tink.Registry');

/**
 * HybridDecryptFactory allows for obtaining an HybridDecrypt primitive from
 * a KeysetHandle.
 *
 * HybridDecryptFactory gets primitives from the Registry, which can be
 * initialized via a convenience method from HybridConfig class. Here is an
 * example how HybridDecrypt primitive may be obtained and used:
 *
 * HybridConfig.register();
 * const keysetHandle = ...;
 * const hybridDecrypt = await HybridDecryptFactory.getPrimitive(keysetHandle);
 *
 * const ciphertext = ...;
 * const contextInfo = ...;
 * const plaintext = await hybridDecrypt.decrypt(ciphertext, contextInfo);
 *
 * @final
 */
class HybridDecryptFactory {
  /**
   * Returns a HybridDecrypt-primitive that uses key material from the keyset
   * given via keysetHandle. If opt_customKeyManager is defined then the
   * provided key manager is used to instantiate primitives. Otherwise key
   * manager from Registry is used.
   *
   * @param {!KeysetHandle} keysetHandle
   * @param {?KeyManager.KeyManager=} opt_customKeyManager
   *
   * @return {!Promise<!HybridDecrypt>}
   */
  static async getPrimitive(keysetHandle, opt_customKeyManager) {
    Registry.registerPrimitiveWrapper(new HybridDecryptWrapper());

    return keysetHandle.getPrimitive(HybridDecrypt, opt_customKeyManager);
  }
}

exports = HybridDecryptFactory;
