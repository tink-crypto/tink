/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

goog.module('tink.signature.PublicKeySignWrapper');

const Bytes = goog.require('google3.third_party.tink.javascript.subtle.bytes');
const PrimitiveSet = goog.require('google3.third_party.tink.javascript.internal.primitive_set');
const {PrimitiveWrapper} = goog.require('google3.third_party.tink.javascript.internal.primitive_wrapper');
const {PublicKeySign} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_sign');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const Validators = goog.require('google3.third_party.tink.javascript.subtle.validators');

/**
 * @final
 */
class WrappedPublicKeySign extends PublicKeySign {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  /** @param {!PrimitiveSet.PrimitiveSet} primitiveSet */
  constructor(primitiveSet) {
    super();
    /** @private @const {!PrimitiveSet.PrimitiveSet} */
    this.primitiveSet_ = primitiveSet;
  }

  /**
   * @param {!PrimitiveSet.PrimitiveSet} primitiveSet
   * @return {!PublicKeySign}
   */
  static newPublicKeySign(primitiveSet) {
    if (!primitiveSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    if (!primitiveSet.getPrimary()) {
      throw new SecurityException('Primary has to be non-null.');
    }
    return new WrappedPublicKeySign(primitiveSet);
  }

  /** @override */
  async sign(data) {
    Validators.requireUint8Array(data);

    const primitive = this.primitiveSet_.getPrimary().getPrimitive();
    const signature = await primitive.sign(data);
    const keyId = this.primitiveSet_.getPrimary().getIdentifier();

    return Bytes.concat(keyId, signature);
  }
}

/**
 * @implements {PrimitiveWrapper<PublicKeySign>}
 */
class PublicKeySignWrapper {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor() {}

  /**
   * @override
   */
  wrap(primitiveSet) {
    return WrappedPublicKeySign.newPublicKeySign(primitiveSet);
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return PublicKeySign;
  }
}

exports = PublicKeySignWrapper;
