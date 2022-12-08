/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as hpkeUtil from '../hpke_util';

import * as hpkeTestUtils from './hpke_test_utils';

/** example `HpkeTestVector[]` with made up values for testing purposes` */
const testVectors:
    hpkeTestUtils.HpkeTestVector[] = hpkeTestUtils.parseTestVectors([{
  'mode': 0,
  'kem_id': 16,
  'kdf_id': 1,
  'aead_id': 1,
  'info': '0001',
  'ikmR': '0002',
  'ikmE': '0003',
  'skRm': '0004',
  'skEm': '0005',
  'pkRm': '0006',
  'pkEm': '0007',
  'enc': '0008',
  'shared_secret': '0009',
  'key_schedule_context': '0010',
  'secret': '0011',
  'key': '0012',
  'base_nonce': '0013',
  'exporter_secret': '0014',
  'encryptions': [
    {'aad': '0015', 'ciphertext': '0016', 'nonce': '0017', 'plaintext': '0018'}
  ],
  'exports': [{'exporter_context': '', 'L': 0, 'exported_value': ''}]
}]);

describe('hpkeTestUtils', () => {
  describe('HpkeTestVector', () => {
    it('should be well formed', async () => {
      const testVector: hpkeTestUtils.HpkeTestVector = testVectors[0];
      expect(testVector.mode).toEqual(hpkeUtil.BASE_MODE);
      expect(testVector.kemId).toEqual(hpkeUtil.P256_HKDF_SHA256_KEM_ID);
      expect(testVector.kdfId).toEqual(hpkeUtil.HKDF_SHA256_KDF_ID);
      expect(testVector.aeadId).toEqual(hpkeUtil.AES_128_GCM_AEAD_ID);
      expect(testVector.info).toEqual(new Uint8Array([0, 0x0001]));
      expect(testVector.recipientPrivateKey).toEqual(new Uint8Array([
        0, 0x0004
      ]));
      expect(testVector.senderPrivateKey).toEqual(new Uint8Array([0, 0x0005]));
      expect(testVector.recipientPublicKey).toEqual(new Uint8Array([
        0, 0x0006
      ]));
      expect(testVector.senderPublicKey).toEqual(new Uint8Array([0, 0x0007]));
      expect(testVector.encapsulatedKey).toEqual(new Uint8Array([0, 0x0008]));
      expect(testVector.sharedSecret).toEqual(new Uint8Array([0, 0x0009]));
      expect(testVector.keyScheduleContext).toEqual(new Uint8Array([
        0, 0x0010
      ]));
      expect(testVector.secret).toEqual(new Uint8Array([0, 0x0011]));
      expect(testVector.key).toEqual(new Uint8Array([0, 0x0012]));
      expect(testVector.baseNonce).toEqual(new Uint8Array([0, 0x0013]));
    });

    it('encryption should be well formed', async () => {
      const testVector: hpkeTestUtils.HpkeTestVector = testVectors[0];
      expect(testVector.encryptions[0].associatedData).toEqual(new Uint8Array([
        0, 0x0015
      ]));
      expect(testVector.encryptions[0].ciphertext).toEqual(new Uint8Array([
        0, 0x0016
      ]));
      expect(testVector.encryptions[0].nonce).toEqual(new Uint8Array([
        0, 0x0017
      ]));
      expect(testVector.encryptions[0].plaintext).toEqual(new Uint8Array([
        0, 0x0018
      ]));
    });
  });

});
