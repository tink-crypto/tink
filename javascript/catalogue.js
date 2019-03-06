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

goog.module('tink.Catalogue');

const KeyManager = goog.require('tink.KeyManager');

/**
 * A catalogue of KeyManager objects.
 *
 * It is a map from a tuple (key type, primitive name) to KeyManager objects,
 * that determines the key manager that handles the keys of the given key type.
 *
 * Tink includes default per-primitive catalogues, but it also supports custom
 * catalogues to enable user-defined configuration of run-time environment via
 * Registry.
 *
 * The template parameter P denotes the primitive which is handled by this
 * catalogue.
 *
 * @template P
 * @record
 */
class Catalogue {
  /**
   * Return a KeyManager which handles given key type and primitive name such
   * that its version is at least minimum version.
   *
   * If there is no such primitive throws SecurityException
   *
   * @param {string} typeUrl -- key type
   * @param {string} primitiveName
   * @param {number} minVersion
   *
   * @return {!KeyManager.KeyManager<P>}
   */
  getKeyManager(typeUrl, primitiveName, minVersion) {}
}

exports = Catalogue;
