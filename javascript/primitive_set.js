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

const CryptoFormat = goog.require('tink.CryptoFormat');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const {PbKeyStatusType, PbKeyset, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

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
   * @param {!PbOutputPrefixType} outputPrefixType
   */
  constructor(primitive, identifier, keyStatus, outputPrefixType) {
    /** @const @private {!P} */
    this.primitive_ = primitive;
    /** @const @private {!Uint8Array} */
    this.identifier_ = identifier;
    /** @const @private {!PbKeyStatusType} */
    this.status_ = keyStatus;
    /** @const @private {!PbOutputPrefixType} */
    this.outputPrefixType_ = outputPrefixType;
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

  /**
   * @return {!PbOutputPrefixType}
   */
  getOutputPrefixType() {
    return this.outputPrefixType_;
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
  /**
   * @param {!Object} primitiveType
   */
  constructor(primitiveType) {
    /**
     * @private {!Object}
     */
    this.primitiveType_ = primitiveType;
    /**
     * @private {?Entry<P>}
     */
    this.primary_ = null;
    // Keys have to be stored as strings as two Uint8Arrays holding the same
    // digits are still different objects.
    /**
     * @private {!Map<string, !Array<!Entry<P>>>}
     */
    this.identifierToPrimitivesMap_ = new Map();
  }

  /**
   * Returns the type of primitives contained in this set.
   *
   * @return {!Object}
   */
  getPrimitiveType() {
    return this.primitiveType_;
  }

  /**
   * Creates an entry in the primitive table and returns it.
   *
   * @param {!P} primitive
   * @param {!PbKeyset.Key} key
   *
   * @return {!Entry<P>}
   */
  addPrimitive(primitive, key) {
    if (!primitive) {
      throw new SecurityException('Primitive has to be non null.');
    }
    if (!key) {
      throw new SecurityException('Key has to be non null.');
    }

    const identifier = CryptoFormat.getOutputPrefix(key);
    const entry = new Entry(primitive, identifier, key.getStatus(),
        key.getOutputPrefixType());

    this.addPrimitiveToMap_(entry);

    return entry;
  }

  /**
   * Returns the entry with the primary primitive.
   *
   * @return {?Entry<P>}
   */
  getPrimary() {
    return this.primary_;
  }

  /**
   * Sets given Entry as the primary one.
   *
   * @param {!Entry<P>} primitive
   */
  setPrimary(primitive) {
    if (!primitive) {
      throw new SecurityException('Primary cannot be set to null.');
    }

    if (primitive.getKeyStatus() != PbKeyStatusType.ENABLED) {
      throw new SecurityException('Primary has to be enabled.');
    }

    // There has to be exactly one key enabled with this identifier.
    const entries = this.getPrimitives(primitive.getIdentifier());
    let entryFound = false;
    const entriesLength = entries.length;
    for (let i = 0; i < entriesLength; i++) {
      if (entries[i].getKeyStatus() === PbKeyStatusType.ENABLED) {
        entryFound = true;
        break;
      }
    }
    if (!entryFound) {
      throw new SecurityException(
          'Primary cannot be set to an entry which is ' +
          'not held by this primitive set.');
    }

    this.primary_ = primitive;
  }

  /**
   * Returns all primitives using RAW prefix.
   *
   * @return {!Array<!Entry<P>>}
   */
  getRawPrimitives() {
    return this.getPrimitives(CryptoFormat.RAW_PREFIX);
  }

  /**
   * Returns the entries with primitive identified with identifier.
   *
   * @param {!Uint8Array} identifier
   *
   * @return {!Array<!Entry<P>>}
   */
  getPrimitives(identifier) {
    const result = this.getPrimitivesFromMap_(identifier);

    if (!result) {
      return [];
    } else {
      return result;
    }
  }

  /**
   * Returns a set of primitives which corresponds to the given identifier.
   *
   * @private
   * @param {!Uint8Array|string} identifier
   *
   * @return {!Array<!Entry<P>>|undefined}
   */
  getPrimitivesFromMap_(identifier) {
    if (identifier instanceof Uint8Array) {
      identifier = [...identifier].toString();
    }
    return this.identifierToPrimitivesMap_.get(identifier);
  }

  /**
   * Add primitive to map.
   *
   * @private
   * @param {!Entry<P>} entry
   */
  addPrimitiveToMap_(entry) {
    const identifier = entry.getIdentifier();
    const id = [...identifier].toString();

    let existing = this.getPrimitivesFromMap_(id);

    if (!existing) {
      this.identifierToPrimitivesMap_.set(id, [entry]);
    } else {
      existing.push(entry);
      this.identifierToPrimitivesMap_.set(id, existing);
    }
  }
}

exports = {
  Entry,
  PrimitiveSet,
};
