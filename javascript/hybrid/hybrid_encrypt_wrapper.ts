/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as PrimitiveSet from '../internal/primitive_set';
import {PrimitiveWrapper} from '../internal/primitive_wrapper';
import * as Bytes from '../subtle/bytes';

import {HybridEncrypt} from './internal/hybrid_encrypt';

/**
 * @final
 */
class WrappedHybridEncrypt extends HybridEncrypt {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor(private readonly hybridEncryptPrimitiveSet:
                  PrimitiveSet.PrimitiveSet<HybridEncrypt>) {
    super();
  }

  static newHybridEncrypt(hybridEncryptPrimitiveSet:
                              PrimitiveSet.PrimitiveSet<HybridEncrypt>):
      HybridEncrypt {
    if (!hybridEncryptPrimitiveSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    if (!hybridEncryptPrimitiveSet.getPrimary()) {
      throw new SecurityException('Primary has to be non-null.');
    }
    return new WrappedHybridEncrypt(hybridEncryptPrimitiveSet);
  }

  async encrypt(plaintext: Uint8Array, opt_contextInfo?: Uint8Array) {
    if (!plaintext) {
      throw new SecurityException('Plaintext has to be non-null.');
    }
    const primary = this.hybridEncryptPrimitiveSet.getPrimary();
    if (!primary) {
      throw new SecurityException('Primary not set.');
    }
    const primitive = primary.getPrimitive();
    const ciphertext = await primitive.encrypt(plaintext, opt_contextInfo);
    const keyId = primary.getIdentifier();
    return Bytes.concat(keyId, ciphertext);
  }
}

export class HybridEncryptWrapper implements PrimitiveWrapper<HybridEncrypt> {
  /**
   */
  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<HybridEncrypt>) {
    return WrappedHybridEncrypt.newHybridEncrypt(primitiveSet);
  }

  /**
   */
  getPrimitiveType() {
    return HybridEncrypt;
  }
}
