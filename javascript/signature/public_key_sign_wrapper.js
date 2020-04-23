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

goog.module('tink.signature.PublicKeySignWrapper');

const Bytes = goog.require('tink.subtle.Bytes');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PrimitiveWrapper = goog.require('tink.PrimitiveWrapper');
const {PublicKeySign} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_sign');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const Validators = goog.require('tink.subtle.Validators');

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
