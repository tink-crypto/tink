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

goog.module('tink.hybrid.HybridDecryptWrapper');

const CryptoFormat = goog.require('tink.CryptoFormat');
const HybridDecrypt = goog.require('tink.HybridDecrypt');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PrimitiveWrapper = goog.require('tink.PrimitiveWrapper');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * @implements {HybridDecrypt}
 * @final
 */
class WrappedHybridDecrypt {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  /** @param {!PrimitiveSet.PrimitiveSet<!HybridDecrypt>} hybridDecryptPrimitiveSet */
  constructor(hybridDecryptPrimitiveSet) {
    /** @private @const {!PrimitiveSet.PrimitiveSet<!HybridDecrypt>} */
    this.primitiveSet_ = hybridDecryptPrimitiveSet;
  }

  /**
   * @param {!PrimitiveSet.PrimitiveSet<!HybridDecrypt>} hybridDecryptPrimitiveSet
   * @return {!HybridDecrypt}
   */
  static newHybridDecrypt(hybridDecryptPrimitiveSet) {
    if (!hybridDecryptPrimitiveSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    return new WrappedHybridDecrypt(hybridDecryptPrimitiveSet);
  }

  /** @override */
  async decrypt(ciphertext, opt_contextInfo) {
    if (!ciphertext) {
      throw new SecurityException('Ciphertext has to be non-null.');
    }

    if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
      const keyId = ciphertext.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE);
      const primitives = await this.primitiveSet_.getPrimitives(keyId);

      const rawCiphertext = ciphertext.subarray(
          CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
      let /** @type {!Uint8Array} */ decryptedText;
      try {
        decryptedText = await this.tryDecryption_(
            primitives, rawCiphertext, opt_contextInfo);
      } catch (/** @type {!Object} */e) {
      }

      if (decryptedText) {
        return decryptedText;
      }
    }

    const primitives = await this.primitiveSet_.getRawPrimitives();
    return await this.tryDecryption_(primitives, ciphertext, opt_contextInfo);
  }

  /**
   * Tries to decrypt the ciphertext using each entry in primitives and
   * returns the ciphertext decrypted by first primitive which succeed. It
   * throws an exception if no entry succeeds.
   *
   * @param {!Array<!PrimitiveSet.Entry<!HybridDecrypt>>} primitives
   * @param {!Uint8Array} ciphertext
   * @param {?Uint8Array=} opt_contextInfo
   *
   * @return {!Promise<!Uint8Array>}
   * @private
   */
  async tryDecryption_(primitives, ciphertext, opt_contextInfo) {
    const primitivesLength = primitives.length;
    for (let i = 0; i < primitivesLength; i++) {
      if (primitives[i].getKeyStatus() != PbKeyStatusType.ENABLED) {
        continue;
      }
      const primitive = primitives[i].getPrimitive();

      let decryptionResult;
      try {
        decryptionResult = await primitive.decrypt(ciphertext, opt_contextInfo);
      } catch (/** @type {!Object} */e) {
        continue;
      }
      return decryptionResult;
    }
    throw new SecurityException('Decryption failed for the given ciphertext.');
  }
}

/**
 * @implements {PrimitiveWrapper<!HybridDecrypt>}
 */
class HybridDecryptWrapper {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor() {}

  /**
   * @override
   */
  wrap(primitiveSet) {
    return WrappedHybridDecrypt.newHybridDecrypt(primitiveSet);
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return HybridDecrypt;
  }
}

exports = HybridDecryptWrapper;
