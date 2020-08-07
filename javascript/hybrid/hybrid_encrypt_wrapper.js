/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

goog.module('tink.hybrid.HybridEncryptWrapper');

const Bytes = goog.require('google3.third_party.tink.javascript.subtle.bytes');
const {HybridEncrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_encrypt');
const PrimitiveSet = goog.require('google3.third_party.tink.javascript.internal.primitive_set');
const {PrimitiveWrapper} = goog.require('google3.third_party.tink.javascript.internal.primitive_wrapper');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');

/**
 * @final
 */
class WrappedHybridEncrypt extends HybridEncrypt {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  /** @param {!PrimitiveSet.PrimitiveSet} hybridEncryptPrimitiveSet */
  constructor(hybridEncryptPrimitiveSet) {
    super();
    /** @private @const {!PrimitiveSet.PrimitiveSet} */
    this.hybridEncryptPrimitiveSet_ = hybridEncryptPrimitiveSet;
  }

  /**
   * @param {!PrimitiveSet.PrimitiveSet} hybridEncryptPrimitiveSet
   * @return {!HybridEncrypt}
   */
  static newHybridEncrypt(hybridEncryptPrimitiveSet) {
    if (!hybridEncryptPrimitiveSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    if (!hybridEncryptPrimitiveSet.getPrimary()) {
      throw new SecurityException('Primary has to be non-null.');
    }
    return new WrappedHybridEncrypt(hybridEncryptPrimitiveSet);
  }

  /** @override */
  async encrypt(plaintext, opt_contextInfo) {
    if (!plaintext) {
      throw new SecurityException('Plaintext has to be non-null.');
    }
    const primitive =
        this.hybridEncryptPrimitiveSet_.getPrimary().getPrimitive();
    const ciphertext = await primitive.encrypt(plaintext, opt_contextInfo);
    const keyId = this.hybridEncryptPrimitiveSet_.getPrimary().getIdentifier();

    return Bytes.concat(keyId, ciphertext);
  }
}

/**
 * @implements {PrimitiveWrapper<HybridEncrypt>}
 */
class HybridEncryptWrapper {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor() {}

  /**
   * @override
   */
  wrap(primitiveSet) {
    return WrappedHybridEncrypt.newHybridEncrypt(primitiveSet);
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return HybridEncrypt;
  }
}

exports = HybridEncryptWrapper;
