/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';

import {CryptoFormat} from './crypto_format';
import {PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from './proto';
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
  private primary: Entry<P>|null = null;

  // Keys have to be stored as strings as two Uint8Arrays holding the same
  // digits are still different objects.
  private readonly identifierToPrimitivesMap: Map<string, Array<Entry<P>>>;

  constructor(private readonly primitiveType: Constructor<P>) {
    this.identifierToPrimitivesMap = new Map();
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
  addPrimitive(primitive: P, key: PbKeysetKey): Entry<P> {
    if (!primitive) {
      throw new SecurityException('Primitive has to be non null.');
    }
    if (!key) {
      throw new SecurityException('Key has to be non null.');
    }
    const identifier = CryptoFormat.getOutputPrefix(key);
    const entry = new Entry(
        primitive, identifier, key.getStatus(), key.getOutputPrefixType());
    this.addPrimitiveToMap(entry);
    return entry;
  }

  /**
   * Returns the entry with the primary primitive.
   *
   */
  getPrimary(): Entry<P>|null {
    return this.primary;
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
    this.primary = primitive;
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
    const result = this.getPrimitivesFromMap(identifier);
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
  private getPrimitivesFromMap(identifier: Uint8Array|
                               string): Array<Entry<P>>|undefined {
    if (identifier instanceof Uint8Array) {
      identifier = [...identifier].toString();
    }
    return this.identifierToPrimitivesMap.get(identifier);
  }

  /**
   * Add primitive to map.
   *
   */
  private addPrimitiveToMap(entry: Entry<P>) {
    const identifier = entry.getIdentifier();
    const id = [...identifier].toString();
    const existing = this.getPrimitivesFromMap(id);
    if (!existing) {
      this.identifierToPrimitivesMap.set(id, [entry]);
    } else {
      existing.push(entry);
      this.identifierToPrimitivesMap.set(id, existing);
    }
  }
}
