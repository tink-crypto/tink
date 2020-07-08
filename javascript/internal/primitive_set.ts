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
import {SecurityException} from '../exception/security_exception';

import {CryptoFormat} from './crypto_format';
import {PbKeyset, PbKeyStatusType, PbOutputPrefixType} from './proto';
import {Constructor} from './util';

/**
 * Auxiliary class for PrimitiveSet
 * Entry-objects hold individual instances of primitives in the set.
 *
 * @template P
 * @final
 */
export class Entry<P> {
  constructor(
      private readonly primitive: P, private readonly identifier: Uint8Array,
      private readonly keyStatus: PbKeyStatusType,
      private readonly outputPrefixType: PbOutputPrefixType) {}

  getPrimitive(): P {
    return this.primitive;
  }

  getIdentifier(): Uint8Array {
    return this.identifier;
  }

  getKeyStatus(): PbKeyStatusType {
    return this.keyStatus;
  }

  getOutputPrefixType(): PbOutputPrefixType {
    return this.outputPrefixType;
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
 * @final
 */
export class PrimitiveSet<P> {
  private primary_: Entry<P>|null = null;

  // Keys have to be stored as strings as two Uint8Arrays holding the same
  // digits are still different objects.
  private readonly identifierToPrimitivesMap_: Map<string, Array<Entry<P>>>;

  constructor(private readonly primitiveType: Constructor<P>) {
    this.identifierToPrimitivesMap_ = new Map();
  }

  /**
   * Returns the type of primitives contained in this set.
   *
   */
  getPrimitiveType(): Constructor<P> {
    return this.primitiveType;
  }

  /**
   * Creates an entry in the primitive table and returns it.
   *
   *
   */
  addPrimitive(primitive: P, key: PbKeyset.Key): Entry<P> {
    if (!primitive) {
      throw new SecurityException('Primitive has to be non null.');
    }
    if (!key) {
      throw new SecurityException('Key has to be non null.');
    }
    const identifier = CryptoFormat.getOutputPrefix(key);
    const entry = new Entry(
        primitive, identifier, key.getStatus(), key.getOutputPrefixType());
    this.addPrimitiveToMap_(entry);
    return entry;
  }

  /**
   * Returns the entry with the primary primitive.
   *
   */
  getPrimary(): Entry<P>|null {
    return this.primary_;
  }

  /**
   * Sets given Entry as the primary one.
   *
   */
  setPrimary(primitive: Entry<P>) {
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
   */
  getRawPrimitives(): Array<Entry<P>> {
    return this.getPrimitives(CryptoFormat.RAW_PREFIX);
  }

  /**
   * Returns the entries with primitive identified with identifier.
   *
   *
   */
  getPrimitives(identifier: Uint8Array): Array<Entry<P>> {
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
   *
   */
  private getPrimitivesFromMap_(identifier: Uint8Array|
                                string): Array<Entry<P>>|undefined {
    if (identifier instanceof Uint8Array) {
      identifier = [...identifier].toString();
    }
    return this.identifierToPrimitivesMap_.get(identifier);
  }

  /**
   * Add primitive to map.
   *
   */
  private addPrimitiveToMap_(entry: Entry<P>) {
    const identifier = entry.getIdentifier();
    const id = [...identifier].toString();
    const existing = this.getPrimitivesFromMap_(id);
    if (!existing) {
      this.identifierToPrimitivesMap_.set(id, [entry]);
    } else {
      existing.push(entry);
      this.identifierToPrimitivesMap_.set(id, existing);
    }
  }
}
