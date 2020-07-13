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

goog.module('tink.hybrid.HybridDecryptWrapperTest');
goog.setTestOnly('tink.hybrid.HybridDecryptWrapperTest');

const Bytes = goog.require('google3.third_party.tink.javascript.subtle.bytes');
const {HybridDecrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_decrypt');
const HybridDecryptWrapper = goog.require('tink.hybrid.HybridDecryptWrapper');
const {HybridEncrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_encrypt');
const HybridEncryptWrapper = goog.require('tink.hybrid.HybridEncryptWrapper');
const PrimitiveSet = goog.require('google3.third_party.tink.javascript.internal.primitive_set');
const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const {PbKeyStatusType, PbKeysetKey, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('hybrid decrypt wrapper test', function() {
  it('decrypt, invalid ciphertext', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);
    // Ciphertext which cannot be decrypted by any primitive in the primitive
    // set.
    const ciphertext = new Uint8Array([9, 8, 7, 6, 5, 4, 3]);

    try {
      await hybridDecrypt.decrypt(ciphertext);
      fail('Should throw an exception');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
  });

  it('decrypt, should work', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    // As keys are just dummy keys which do not contain key data, the same key
    // is used for both encrypt and decrypt.
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.TINK,
        /** enabled = */ true);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Get the ciphertext.
    const encryptPrimitiveSet = primitiveSets['encryptPrimitiveSet'];
    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const entry = encryptPrimitiveSet.addPrimitive(encryptPrimitive, key);
    // Has to be set to primary as then it is used in encryption.
    encryptPrimitiveSet.setPrimary(entry);
    const hybridEncrypt = new HybridEncryptWrapper().wrap(encryptPrimitiveSet);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);

    // Create a primitive set containing the primitive which can be used for
    // encryption. Add also few more primitives with the same key as the
    // primitive set should decrypt the ciphertext whenever there is at least
    // one primitive which does not fail to decrypt the ciphertext.
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(
        new DummyHybridDecrypt(Random.randBytes(5)), key);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    decryptPrimitiveSet.addPrimitive(
        new DummyHybridDecrypt(Random.randBytes(5)), key);

    // Decrypt the ciphertext.
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);
    const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

    // Test that the result is the original plaintext.
    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('decrypt, ciphertext encrypted by raw primitive', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    // As keys are just dummy keys which do not contain key data, the same key
    // is used for both encrypt and decrypt.
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ true);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Get the ciphertext.
    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const ciphertext = await encryptPrimitive.encrypt(plaintext);

    // Decrypt the ciphertext.
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);
    const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

    // Test that the result is the original plaintext.
    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('decrypt, with context info', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    const contextInfo = Random.randBytes(10);
    // As keys are just dummy keys which do not contain key data, the same key
    // is used for both encrypt and decrypt.
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ true);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Get the ciphertext.
    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const ciphertext = await encryptPrimitive.encrypt(plaintext, contextInfo);

    // Get primitive for decryption.
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);

    // Check that contextInfo was passed correctly (decryption without
    // contextInfo argument should not work, but with contextInfo it should work
    // properly).
    try {
      await hybridDecrypt.decrypt(ciphertext);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
    const decryptedCiphertext =
        await hybridDecrypt.decrypt(ciphertext, contextInfo);

    // Test that the result is the original plaintext.
    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('decrypt, with disabled primitive', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const plaintext = Random.randBytes(10);
    const key = createDummyKeysetKey(
        /** keyId = */ 0xFFFFFFFF, PbOutputPrefixType.RAW,
        /** enabled = */ false);
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    const encryptPrimitive = new DummyHybridEncrypt(ciphertextSuffix);
    const ciphertext = await encryptPrimitive.encrypt(plaintext);

    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const decryptPrimitive = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(decryptPrimitive, key);
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);

    try {
      await hybridDecrypt.decrypt(ciphertext);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
  });

  it('decrypt, with empty ciphertext', async function() {
    const primitiveSets = createDummyPrimitiveSets();
    const decryptPrimitiveSet = primitiveSets['decryptPrimitiveSet'];
    const hybridDecrypt = new HybridDecryptWrapper().wrap(decryptPrimitiveSet);

    try {
      await hybridDecrypt.decrypt(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.cannotBeDecrypted());
    }
  });
});

/** @final */
class ExceptionText {
  /** @return {string} */
  static nullPrimitiveSet() {
    return 'SecurityException: Primitive set has to be non-null.';
  }
  /** @return {string} */
  static cannotBeDecrypted() {
    return 'SecurityException: Decryption failed for the given ciphertext.';
  }
  /** @return {string} */
  static nullCiphertext() {
    return 'SecurityException: Ciphertext has to be non-null.';
  }
}

/**
 * Function for creating keys for testing purposes.
 *
 * @param {number} keyId
 * @param {!PbOutputPrefixType} outputPrefix
 * @param {boolean} enabled
 *
 * @return {!PbKeysetKey}
 */
const createDummyKeysetKey = function(keyId, outputPrefix, enabled) {
  let key = new PbKeysetKey();

  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  key.setOutputPrefixType(outputPrefix);
  key.setKeyId(keyId);

  return key;
};

/**
 * Creates a primitive sets for HybridEncrypt and HybridDecrypt with
 * 'numberOfPrimitives' primitives. The keys corresponding to the primitives
 * have ids from the set [1, ..., numberOfPrimitives] and the primitive
 * corresponding to key with id 'numberOfPrimitives' is set to be primary
 * whenever opt_withPrimary is set to true (where true is the default value).
 *
 * @param {boolean=} opt_withPrimary
 * @return {{encryptPrimitiveSet:!PrimitiveSet.PrimitiveSet,
 *     decryptPrimitiveSet:!PrimitiveSet.PrimitiveSet}}
 */
const createDummyPrimitiveSets = function(opt_withPrimary = true) {
  const numberOfPrimitives = 5;

  const encryptPrimitiveSet = new PrimitiveSet.PrimitiveSet(DummyHybridEncrypt);
  const decryptPrimitiveSet = new PrimitiveSet.PrimitiveSet(DummyHybridDecrypt);
  for (let i = 1; i < numberOfPrimitives; i++) {
    let /** @type {!PbOutputPrefixType} */ outputPrefix;
    switch (i % 3) {
      case 0:
        outputPrefix = PbOutputPrefixType.TINK;
        break;
      case 1:
        outputPrefix = PbOutputPrefixType.LEGACY;
        break;
      default:
        outputPrefix = PbOutputPrefixType.RAW;
    }
    const key =
        createDummyKeysetKey(i, outputPrefix, /* enabled = */ i % 4 < 2);
    const ciphertextSuffix = new Uint8Array([0, 0, i]);
    const hybridEncrypt = new DummyHybridEncrypt(ciphertextSuffix);
    encryptPrimitiveSet.addPrimitive(hybridEncrypt, key);
    const hybridDecrypt = new DummyHybridDecrypt(ciphertextSuffix);
    decryptPrimitiveSet.addPrimitive(hybridDecrypt, key);
  }

  const key = createDummyKeysetKey(
      numberOfPrimitives, PbOutputPrefixType.TINK, /* enabled = */ true);
  const ciphertextSuffix = new Uint8Array([0, 0, numberOfPrimitives]);
  const hybridEncrypt = new DummyHybridEncrypt(ciphertextSuffix);
  const encryptEntry = encryptPrimitiveSet.addPrimitive(hybridEncrypt, key);
  const hybridDecrypt = new DummyHybridDecrypt(ciphertextSuffix);
  const decryptEntry = decryptPrimitiveSet.addPrimitive(hybridDecrypt, key);
  if (opt_withPrimary) {
    encryptPrimitiveSet.setPrimary(encryptEntry);
    decryptPrimitiveSet.setPrimary(decryptEntry);
  }

  return {
    'encryptPrimitiveSet': encryptPrimitiveSet,
    'decryptPrimitiveSet': decryptPrimitiveSet
  };
};

/**
 * @final
 */
class DummyHybridEncrypt extends HybridEncrypt {
  /** @param {!Uint8Array} ciphertextSuffix */
  constructor(ciphertextSuffix) {
    super();
    this.ciphertextSuffix_ = ciphertextSuffix;
  }
  /** @override */
  async encrypt(plaintext, opt_contextInfo) {
    const ciphertext = Bytes.concat(plaintext, this.ciphertextSuffix_);
    if (opt_contextInfo) {
      return Bytes.concat(ciphertext, opt_contextInfo);
    }
    return ciphertext;
  }
}

/**
 * @final
 */
class DummyHybridDecrypt extends HybridDecrypt {
  /** @param {!Uint8Array} ciphertextSuffix */
  constructor(ciphertextSuffix) {
    super();
    this.ciphertextSuffix_ = ciphertextSuffix;
  }

  /** @override */
  async decrypt(ciphertext, opt_contextInfo) {
    if (opt_contextInfo) {
      const infoLength = opt_contextInfo.length;
      const contextInfo =
          ciphertext.slice(ciphertext.length - infoLength, ciphertext.length);
      if ([...contextInfo].toString() !== [...opt_contextInfo].toString()) {
        throw new SecurityException('Context info does not match.');
      }
      ciphertext = ciphertext.slice(0, ciphertext.length - infoLength);
    }
    const plaintext =
        ciphertext.slice(0, ciphertext.length - this.ciphertextSuffix_.length);
    const suffix = ciphertext.slice(
        ciphertext.length - this.ciphertextSuffix_.length, ciphertext.length);
    if ([...suffix].toString() === [...this.ciphertextSuffix_].toString()) {
      return plaintext;
    }
    throw new SecurityException(ExceptionText.cannotBeDecrypted());
  }
}
