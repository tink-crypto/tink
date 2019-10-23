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

goog.module('tink.aead.AeadWrapper');

const Aead = goog.require('tink.Aead');
const CryptoFormat = goog.require('tink.CryptoFormat');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const PrimitiveWrapper = goog.require('tink.PrimitiveWrapper');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * @implements {Aead}
 * @final
 */
class WrappedAead {
  /**
   * @param {!PrimitiveSet.PrimitiveSet} aeadSet
   */
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor(aeadSet) {
    /** @private @const {!PrimitiveSet.PrimitiveSet} */
    this.aeadSet_ = aeadSet;
  }

  /**
   * @param {!PrimitiveSet.PrimitiveSet} aeadSet
   *
   * @return {!Aead}
   */
  static newAead(aeadSet) {
    if (!aeadSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    if (!aeadSet.getPrimary()) {
      throw new SecurityException('Primary has to be non-null.');
    }
    return new WrappedAead(aeadSet);
  }

  /**
   * @override
   */
  async encrypt(plaintext, opt_associatedData) {
    if (!plaintext) {
      throw new SecurityException('Plaintext has to be non-null.');
    }
    const primitive = this.aeadSet_.getPrimary().getPrimitive();
    const encryptedText =
        await primitive.encrypt(plaintext, opt_associatedData);
    const keyId = this.aeadSet_.getPrimary().getIdentifier();

    const ciphertext = new Uint8Array(keyId.length + encryptedText.length);
    ciphertext.set(keyId, 0);
    ciphertext.set(encryptedText, keyId.length);
    return ciphertext;
  }

  /**
   * @override
   */
  async decrypt(ciphertext, opt_associatedData) {
    if (!ciphertext) {
      throw new SecurityException('Ciphertext has to be non-null.');
    }

    if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
      const keyId = ciphertext.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE);
      const entries = await this.aeadSet_.getPrimitives(keyId);

      const rawCiphertext = ciphertext.subarray(
          CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
      let /** @type {!Uint8Array} */ decryptedText;
      try {
        decryptedText = await this.tryDecryption_(
            entries, rawCiphertext, opt_associatedData);
      } catch (e) {
      }

      if (decryptedText) {
        return decryptedText;
      }
    }

    const entries = await this.aeadSet_.getRawPrimitives();
    const decryptedText =
        await this.tryDecryption_(entries, ciphertext, opt_associatedData);
    return decryptedText;
  }

  /**
   * Tries to decrypt the ciphertext using each entry in entriesArray and
   * returns the ciphertext decrypted by first primitive which succeed. It
   * throws an exception if no entry succeeds.
   *
   * @private
   * @param {!Array<!PrimitiveSet.Entry>} entriesArray
   * @param {!Uint8Array} ciphertext
   * @param {?Uint8Array=} opt_associatedData
   *
   * @return {!Promise<!Uint8Array>}
   */
  async tryDecryption_(entriesArray, ciphertext, opt_associatedData) {
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

/**
 * @implements {PrimitiveWrapper<Aead>}
 */
class AeadWrapper {
  /**
   * @private
   */
  constructor() {}

  /**
   * @override
   */
  wrap(primitiveSet) {
    return WrappedAead.newAead(primitiveSet);
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return Aead;
  }

  static register() {
    Registry.registerPrimitiveWrapper(new AeadWrapper());
  }
}

exports = AeadWrapper;
