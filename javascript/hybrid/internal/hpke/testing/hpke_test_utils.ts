/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as bytes from '../../../../subtle/bytes';
import * as hpkeUtil from '../hpke_util';

/** Interface representing individual test vector. */
export interface HpkeTestVector {
  mode: Uint8Array;
  kemId: Uint8Array;
  kdfId: Uint8Array;
  aeadId: Uint8Array;
  info: Uint8Array;
  senderPublicKey: Uint8Array;
  senderPrivateKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  recipientPrivateKey: Uint8Array;
  encapsulatedKey: Uint8Array;
  sharedSecret: Uint8Array;
  keyScheduleContext: Uint8Array;
  secret: Uint8Array;
  key: Uint8Array;
  baseNonce: Uint8Array;
  encryptions: Array<{
    nonce: Uint8Array,
    plaintext: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array,
  }>;
}

/**
 * Parses JSON-formatted test vectors from `HpkeTestVectorJson[]` into an array
 * of `HpkeTestVector`s.
 *
 * Example test vectors are available at
 * https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json.
 */
export function parseTestVectors(testArray: HpkeTestVectorJson[]):
    HpkeTestVector[] {
  const testVectors: HpkeTestVector[] = [];

  for (const testVector of testArray) {
    const mode = hpkeUtil.numberToByteArray(1, testVector.mode);
    const kemId = hpkeUtil.numberToByteArray(2, testVector.kem_id);
    const kdfId = hpkeUtil.numberToByteArray(2, testVector.kdf_id);
    const aeadId = hpkeUtil.numberToByteArray(2, testVector.aead_id);

    // Filter out test vectors for unsupported modes and/or KEMs.
    if (!bytes.isEqual(mode, hpkeUtil.BASE_MODE) ||
        !(bytes.isEqual(kemId, hpkeUtil.P256_HKDF_SHA256_KEM_ID) ||
          bytes.isEqual(kemId, hpkeUtil.P521_HKDF_SHA512_KEM_ID)) ||
        !(bytes.isEqual(kdfId, hpkeUtil.HKDF_SHA256_KDF_ID) ||
          bytes.isEqual(kdfId, hpkeUtil.HKDF_SHA512_KDF_ID)) ||
        !(bytes.isEqual(aeadId, hpkeUtil.AES_128_GCM_AEAD_ID) ||
          bytes.isEqual(aeadId, hpkeUtil.AES_256_GCM_AEAD_ID))) {
      continue;
    }
    const testEncryptions = [];

    for (const encryption of testVector.encryptions) {
      const testEncryption = {
        plaintext: bytes.fromHex(encryption.plaintext),
        associatedData: bytes.fromHex(encryption.aad),
        nonce: bytes.fromHex(encryption.nonce),
        ciphertext: bytes.fromHex(encryption.ciphertext),
      };
      testEncryptions.push(testEncryption);
    }

    const hpkeTestVector: HpkeTestVector = {
      mode,
      kemId,
      kdfId,
      aeadId,
      info: bytes.fromHex(testVector.info),
      senderPublicKey: bytes.fromHex(testVector.pkEm),
      senderPrivateKey: bytes.fromHex(testVector.skEm),
      recipientPublicKey: bytes.fromHex(testVector.pkRm),
      recipientPrivateKey: bytes.fromHex(testVector.skRm),
      encapsulatedKey: bytes.fromHex(testVector.enc),
      sharedSecret: bytes.fromHex(testVector.shared_secret),
      keyScheduleContext: bytes.fromHex(testVector.key_schedule_context),
      secret: bytes.fromHex(testVector.secret),
      key: bytes.fromHex(testVector.key),
      baseNonce: bytes.fromHex(testVector.base_nonce),
      encryptions: testEncryptions,
    };

    testVectors.push(hpkeTestVector);
  }
  return testVectors;
}

/**
 * JSON representation of a test vector as stored in the BoringSSL HPKE test
 * vectors. Used to read and parse the vectors for testing.
 *
 * Example test vectors are available at
 * https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json.
 */
export declare interface HpkeTestVectorJson {
  mode: number;
  kem_id: number;
  kdf_id: number;
  aead_id: number;
  info: string;
  ikmR: string;
  ikmE: string;
  skRm: string;
  skEm: string;
  pkRm: string;
  pkEm: string;
  enc: string;
  shared_secret: string;
  key_schedule_context: string;
  secret: string;
  key: string;
  base_nonce: string;
  exporter_secret: string;
  encryptions: Encryption[];
  exports: Export[];
}

declare interface Encryption {
  aad: string;
  ciphertext: string;
  nonce: string;
  plaintext: string;
}

declare interface Export {
  exporter_context: string;
  L: number;
  exported_value: string;
}
