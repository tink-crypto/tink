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

goog.module('tink.PrimitiveSet');

const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * Auxiliary class for PrimitiveSet
 * Entry-objects hold individual instances of primitives in the set.
 *
 * @template P
 * @final
 */
class Entry {
  /**
   * @param {!P} primitive
   * @param {!Uint8Array} identifier
   * @param {!PbKeyStatusType} keyStatus
   */
  constructor(primitive, identifier, keyStatus) {
    /** @const @private {!P} */
    this.primitive_ = primitive;
    /** @const @private {!Uint8Array} */
    this.identifier_ = identifier;
    /** @const @private {!PbKeyStatusType} */
    this.status_ = keyStatus;
  }

  /**
   * @return {!P}
   */
  getPrimitive() {
    return this.primitive_;
  }

  /**
   * @return {!Uint8Array}
   */
  getIdentifier() {
    return this.identifier_;
  }

  /**
   * @return {!PbKeyStatusType}
   */
  getKeyStatus() {
    return this.status_;
  }
}

/**
 * A container class for a set of primitives (i.e. implementations of
 * cryptographic primitives offered by Tink). It provides also additional
 * properties for the primitives it holds. In particular, one of the primitives
 * in the set can be distinguished as "the primary" one.
 *
 * PrimitiveSet is an auxiliary class used for supporting key rotation:
 * primitives in a set correspond to keys in a keyset. Users will usually work
 * with primitive instances which essentially wrap primitive sets. For example
 * an instance of an Aead-primitive for a given keyset holds a set of
 * Aead-primitives corresponding to the keys in the keyset, and uses the set
 * members to do the actual crypto operations: to encrypt data the primary
 * Aead-primitive from the set is used, and upon decryption the ciphertext's
 * prefix determines the identifier of the primitive from the set.
 *
 * PrimitiveSet is a public class to allow its use in implementations of custom
 * primitives.
 *
 * @template P
 * @final
 */
class PrimitiveSet {
  constructor() {
    /**
     * @const @private
     */
    this.primary_ = null;
  }

  /**
   * Creates an entry in the primitive table and returns it.
   *
   * @param {!P} primitive
   * @param {!PbKeyset.Key} key
   *
   * @return {!Promise<!Entry<P>>}
   */
  async addPrimitive(primitive, key) {
    // TODO implement
    throw new SecurityException(
        'PrimitiveSet -- addPrimitive: Not implemented yet.');
  }

  /**
   * Returns the entry with the primary primitive.
   *
   * @return {!Promise<!Entry<P>>}
   */
  async getPrimary() {
    // TODO implement
    throw new SecurityException(
        'PrimitiveSet -- getPrimary: Not implemented yet.');
  }

  /**
   * Sets given Entry as the primary one.
   *
   * @param {!Promise<!Entry<P>>} primitive
   */
  async setPrimary(primitive) {
    // TODO implement
    throw new SecurityException(
        'PrimitiveSet -- setPrimary: Not implemented yet.');
  }

  /**
   * Returns all primitives using RAW prefix.
   *
   * @return {!Promise<!Array<Entry<P>>>}
   */
  async getRawPrimitives() {
    // TODO implement
    throw new SecurityException(
        'PrimitiveSet -- getRawPrimitives: Not implemented yet.');
  }

  /**
   * Returns the entries with primitive identified with identifier.
   *
   * @param {!Uint8Array} identifier
   *
   * @return {!Promise<!Array<Entry<P>>>}
   */
  async getPrimitives(identifier) {
    // TODO implement
    throw new SecurityException(
        'PrimitiveSet -- getPrimitives: Not implemented yet.');
  }
}

exports = {
  Entry,
  PrimitiveSet,
};
