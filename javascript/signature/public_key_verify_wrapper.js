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

goog.module('tink.signature.PublicKeyVerifyWrapper');

const CryptoFormat = goog.require('tink.CryptoFormat');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PrimitiveWrapper = goog.require('tink.PrimitiveWrapper');
const PublicKeyVerify = goog.require('tink.PublicKeyVerify');
const SecurityException = goog.require('tink.exception.SecurityException');
const Validators = goog.require('tink.subtle.Validators');

/**
 * @implements {PublicKeyVerify}
 * @final
 */
class WrappedPublicKeyVerify {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  /** @param {!PrimitiveSet.PrimitiveSet} primitiveSet */
  constructor(primitiveSet) {
    /** @private @const {!PrimitiveSet.PrimitiveSet} */
    this.primitiveSet_ = primitiveSet;
  }

  /**
   * @param {!PrimitiveSet.PrimitiveSet} primitiveSet
   * @return {!PublicKeyVerify}
   */
  static newPublicKeyVerify(primitiveSet) {
    if (!primitiveSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    return new WrappedPublicKeyVerify(primitiveSet);
  }

  /** @override */
  async verify(signature, data) {
    Validators.requireUint8Array(signature);
    Validators.requireUint8Array(data);

    if (signature.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
      const keyId = signature.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE);
      const primitives = await this.primitiveSet_.getPrimitives(keyId);

      const rawSignature = signature.subarray(
          CryptoFormat.NON_RAW_PREFIX_SIZE, signature.length);
      let /** @type {boolean} */ isValid;
      try {
        isValid = await this.tryVerification_(primitives, rawSignature, data);
      } catch (e) {
        // Ignored.
      }

      if (isValid) {
        return isValid;
      }
    }

    const primitives = await this.primitiveSet_.getRawPrimitives();
    return await this.tryVerification_(primitives, signature, data);
  }

  /**
   * Tries to verify the signature using each entry in primitives. It
   * returns false if no entry succeeds.
   *
   * @param {!Array<!PrimitiveSet.Entry>} primitives
   * @param {!Uint8Array} signature
   * @param {!Uint8Array} data
   *
   * @return {!Promise<boolean>}
   * @private
   */
  async tryVerification_(primitives, signature, data) {
    const primitivesLength = primitives.length;
    for (let i = 0; i < primitivesLength; i++) {
      if (primitives[i].getKeyStatus() != PbKeyStatusType.ENABLED) {
        continue;
      }
      const primitive = primitives[i].getPrimitive();

      let /** @type {boolean} */ isValid;
      try {
        isValid = await primitive.verify(signature, data);
      } catch (e) {
        continue;
      }
      if (isValid) {
        return isValid;
      }
    }
    return false;
  }
}

/**
 * @implements {PrimitiveWrapper<PublicKeyVerify>}
 */
class PublicKeyVerifyWrapper {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor() {}

  /**
   * @override
   */
  wrap(primitiveSet) {
    return WrappedPublicKeyVerify.newPublicKeyVerify(primitiveSet);
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return PublicKeyVerify;
  }
}

exports = PublicKeyVerifyWrapper;
