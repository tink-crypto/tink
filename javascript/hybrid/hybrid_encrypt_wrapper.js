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

goog.module('tink.hybrid.HybridEncryptWrapper');

const Bytes = goog.require('tink.subtle.Bytes');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PrimitiveWrapper = goog.require('tink.PrimitiveWrapper');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * @implements {HybridEncrypt}
 * @final
 */
class WrappedHybridEncrypt {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  /** @param {!PrimitiveSet.PrimitiveSet} hybridEncryptPrimitiveSet */
  constructor(hybridEncryptPrimitiveSet) {
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
