/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {CryptoFormat} from '../internal/crypto_format';
import * as PrimitiveSet from '../internal/primitive_set';
import {PrimitiveWrapper} from '../internal/primitive_wrapper';
import {PbKeyStatusType} from '../internal/proto';
import * as Registry from '../internal/registry';
import {Constructor} from '../internal/util';

import {Aead} from './internal/aead';

/**
 * @final
 */
class WrappedAead extends Aead {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor(private readonly aeadSet: PrimitiveSet.PrimitiveSet<Aead>) {
    super();
  }

  static newAead(aeadSet: PrimitiveSet.PrimitiveSet<Aead>): Aead {
    if (!aeadSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    if (!aeadSet.getPrimary()) {
      throw new SecurityException('Primary has to be non-null.');
    }
    return new WrappedAead(aeadSet);
  }

  /**
   */
  async encrypt(plaintext: Uint8Array, opt_associatedData?: Uint8Array|null):
      Promise<Uint8Array> {
    if (!plaintext) {
      throw new SecurityException('Plaintext has to be non-null.');
    }
    const primary = this.aeadSet.getPrimary()
    if (!primary) {
      throw new SecurityException('Primary has to be non-null.');
    }
    const primitive = primary.getPrimitive();
    const encryptedText =
        await primitive.encrypt(plaintext, opt_associatedData);
    const keyId = primary.getIdentifier();
    const ciphertext = new Uint8Array(keyId.length + encryptedText.length);
    ciphertext.set(keyId, 0);
    ciphertext.set(encryptedText, keyId.length);
    return ciphertext;
  }

  /**
   */
  async decrypt(ciphertext: Uint8Array, opt_associatedData?: Uint8Array|null):
      Promise<Uint8Array> {
    if (!ciphertext) {
      throw new SecurityException('Ciphertext has to be non-null.');
    }
    if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
      const keyId = ciphertext.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE);
      const entries = await this.aeadSet.getPrimitives(keyId);
      const rawCiphertext = ciphertext.subarray(
          CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
      let decryptedText: Uint8Array|undefined;
      try {
        decryptedText = await this.tryDecryption(
            entries, rawCiphertext, opt_associatedData);
      } catch (e) {
      }
      if (decryptedText) {
        return decryptedText;
      }
    }
    const entries = await this.aeadSet.getRawPrimitives();
    const decryptedText =
        await this.tryDecryption(entries, ciphertext, opt_associatedData);
    return decryptedText;
  }

  /**
   * Tries to decrypt the ciphertext using each entry in entriesArray and
   * returns the ciphertext decrypted by first primitive which succeed. It
   * throws an exception if no entry succeeds.
   *
   *
   */
  private async tryDecryption(
      entriesArray: Array<PrimitiveSet.Entry<Aead>>, ciphertext: Uint8Array,
      opt_associatedData?: Uint8Array|null): Promise<Uint8Array> {
    const entriesArrayLength = entriesArray.length;
    for (let i = 0; i < entriesArrayLength; i++) {
      if (entriesArray[i].getKeyStatus() != PbKeyStatusType.ENABLED) {
        continue;
      }
      const primitive = entriesArray[i].getPrimitive();
      let decryptionResult;
      try {
        decryptionResult =
            await primitive.decrypt(ciphertext, opt_associatedData);
      } catch (e) {
        continue;
      }
      return decryptionResult;
    }
    throw new SecurityException('Decryption failed for the given ciphertext.');
  }
}

export class AeadWrapper implements PrimitiveWrapper<Aead> {
  /**
   */
  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<Aead>): Aead {
    return WrappedAead.newAead(primitiveSet);
  }

  /**
   */
  getPrimitiveType(): Constructor<Aead> {
    return Aead;
  }

  static register() {
    Registry.registerPrimitiveWrapper(new AeadWrapper());
  }
}
