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

goog.module('tink.aead.AeadFactory');

const Aead = goog.require('tink.Aead');
const AeadSetWrapper = goog.require('tink.aead.AeadSetWrapper');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const Registry = goog.require('tink.Registry');

/**
 * AeadFactory allows for obtaining an Aead primitive from a KeysetHandle.
 *
 * AeadFactory gets primitives from the Registry, which can be initialized via a
 * convenience method from AeadConfig class. Here is an example how Aead
 * primitive may be obtained:
 *
 * AeadConfig.register();
 * const keysetHandle = ...;
 * const aead = await AeadFactory.getPrimitive(keysetHandle);
 *
 * const plaintext = ...;
 * const aad = ...;
 * const ciphertext = await aead.encrypt(plaintext, aad);
 *
 * @final
 */
class AeadFactory {
  // Returns an Aead-primitive that uses key material from the keyset given via
  // keysetHandle. If opt_customKeyManager is defined then the provided key
  // manager is used to instantiate primitives. Otherwise key manager from
  // Registry is used.
  /**
   * @param {!KeysetHandle} keysetHandle
   * @param {?KeyManager.KeyManager=} opt_customKeyManager
   *
   * @return {!Promise<!Aead>}
   */
  static async getPrimitive(keysetHandle, opt_customKeyManager) {
    const primitives =
        await Registry.getPrimitives(Aead, keysetHandle, opt_customKeyManager);
    return AeadSetWrapper.newAead(primitives);
  }
}

exports = AeadFactory;
