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

import {HybridDecrypt} from './internal/hybrid_decrypt';

/**
 * @final
 */
class WrappedHybridDecrypt extends HybridDecrypt {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor(private readonly hybridDecryptPrimitiveSet:
                  PrimitiveSet.PrimitiveSet<HybridDecrypt>) {
    super();
  }

  static newHybridDecrypt(hybridDecryptPrimitiveSet:
                              PrimitiveSet.PrimitiveSet<HybridDecrypt>):
      HybridDecrypt {
    if (!hybridDecryptPrimitiveSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    return new WrappedHybridDecrypt(hybridDecryptPrimitiveSet);
  }

  async decrypt(ciphertext: Uint8Array, opt_contextInfo?: Uint8Array) {
    if (!ciphertext) {
      throw new SecurityException('Ciphertext has to be non-null.');
    }
    if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
      const keyId = ciphertext.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE);
      const primitives =
          await this.hybridDecryptPrimitiveSet.getPrimitives(keyId);
      const rawCiphertext = ciphertext.subarray(
          CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
      let decryptedText: Uint8Array|undefined;
      try {
        decryptedText = await this.tryDecryption(
            primitives, rawCiphertext, opt_contextInfo);
      } catch (e) {
      }
      if (decryptedText) {
        return decryptedText;
      }
    }
    const primitives = await this.hybridDecryptPrimitiveSet.getRawPrimitives();
    return this.tryDecryption(primitives, ciphertext, opt_contextInfo);
  }

  /**
   * Tries to decrypt the ciphertext using each entry in primitives and
   * returns the ciphertext decrypted by first primitive which succeed. It
   * throws an exception if no entry succeeds.
   *
   *
   */
  private async tryDecryption(
      primitives: Array<PrimitiveSet.Entry<HybridDecrypt>>,
      ciphertext: Uint8Array,
      opt_contextInfo?: Uint8Array|null): Promise<Uint8Array> {
    const primitivesLength = primitives.length;
    for (let i = 0; i < primitivesLength; i++) {
      if (primitives[i].getKeyStatus() != PbKeyStatusType.ENABLED) {
        continue;
      }
      const primitive = primitives[i].getPrimitive();
      let decryptionResult;
      try {
        decryptionResult = await primitive.decrypt(ciphertext, opt_contextInfo);
      } catch (e) {
        continue;
      }
      return decryptionResult;
    }
    throw new SecurityException('Decryption failed for the given ciphertext.');
  }
}

export class HybridDecryptWrapper implements PrimitiveWrapper<HybridDecrypt> {
  /**
   */
  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<HybridDecrypt>) {
    return WrappedHybridDecrypt.newHybridDecrypt(primitiveSet);
  }

  /**
   */
  getPrimitiveType() {
    return HybridDecrypt;
  }
}
