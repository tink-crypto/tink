/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeParams} from '../../../internal/proto';

import {AesGcmHpkeAead} from './aes_gcm_hpke_aead';
import {HkdfHpkeKdf} from './hkdf_hpke_kdf';
import {HpkePrimitiveFactory} from './hpke_primitive_factory';
import * as hpkeUtil from './hpke_util';
import {NistCurvesHpkeKem} from './nist_curves_hpke_kem';

interface TestVector {
  kemId: Uint8Array;
  kdfId: Uint8Array;
  aeadId: Uint8Array;
  params: PbHpkeParams;
}

const TEST_VECTORS: TestVector[] = [
  /** Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM */
  {
    kemId: hpkeUtil.P256_HKDF_SHA256_KEM_ID,
    kdfId: hpkeUtil.HKDF_SHA256_KDF_ID,
    aeadId: hpkeUtil.AES_128_GCM_AEAD_ID,
    params: new PbHpkeParams()
                .setKem(PbHpkeKem.DHKEM_P256_HKDF_SHA256)
                .setKdf(PbHpkeKdf.HKDF_SHA256)
                .setAead(PbHpkeAead.AES_128_GCM)
  },
  /** Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM */
  {
    kemId: hpkeUtil.P521_HKDF_SHA512_KEM_ID,
    kdfId: hpkeUtil.HKDF_SHA512_KDF_ID,
    aeadId: hpkeUtil.AES_256_GCM_AEAD_ID,
    params: new PbHpkeParams()
                .setKem(PbHpkeKem.DHKEM_P521_HKDF_SHA512)
                .setKdf(PbHpkeKdf.HKDF_SHA512)
                .setAead(PbHpkeAead.AES_256_GCM)
  }
];

describe('HpkePrimitiveFactory', () => {
  for (const testInfo of TEST_VECTORS) {
    it('should create valid kem from valid kemId', async () => {
      const kem = HpkePrimitiveFactory.createKemFromId(testInfo.kemId);
      expect(kem instanceof NistCurvesHpkeKem).toBe(true);
      expect(kem.getKemId()).toEqual(testInfo.kemId);
    });

    it('should create valid kdf from valid kdfId', async () => {
      const kdf = HpkePrimitiveFactory.createKdfFromId(testInfo.kdfId);
      expect(kdf instanceof HkdfHpkeKdf).toBe(true);
      expect(kdf.getKdfId()).toEqual(testInfo.kdfId);
    });

    it('should create valid aead from valid aeadId', async () => {
      const aead = HpkePrimitiveFactory.createAeadFromId(testInfo.aeadId);
      expect(aead instanceof AesGcmHpkeAead).toBe(true);
      expect(aead.getAeadId()).toEqual(testInfo.aeadId);
    });
    it('should create valid kem from valid kem param', async () => {
      const kem = HpkePrimitiveFactory.createKemFromParams(testInfo.params);
      expect(kem instanceof NistCurvesHpkeKem).toBe(true);
      expect(kem.getKemId()).toEqual(testInfo.kemId);
    });
    it('should create valid kdf from valid kdf param', async () => {
      const kdf = HpkePrimitiveFactory.createKdfFromParams(testInfo.params);
      expect(kdf instanceof HkdfHpkeKdf).toBe(true);
      expect(kdf.getKdfId()).toEqual(testInfo.kdfId);
    });
    it('should create valid aead from valid aead param', async () => {
      const aead = HpkePrimitiveFactory.createAeadFromParams(testInfo.params);
      expect(aead instanceof AesGcmHpkeAead).toBe(true);
      expect(aead.getAeadId()).toEqual(testInfo.aeadId);
    });
  }

  describe('fails to instantiate from invalid', () => {
    const invalidHpkeParam = new PbHpkeParams()
                                 .setKem(PbHpkeKem.KEM_UNKNOWN)
                                 .setKdf(PbHpkeKdf.KDF_UNKNOWN)
                                 .setAead(PbHpkeAead.AEAD_UNKNOWN);
    it('kem id', async () => {
      try {
        HpkePrimitiveFactory.createKemFromId(new Uint8Array(0));
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KEM identifier');
      }
    });
    it('kdf id', async () => {
      try {
        HpkePrimitiveFactory.createKdfFromId(new Uint8Array(0));
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KDF identifier');
      }
    });
    it('aead id', async () => {
      try {
        HpkePrimitiveFactory.createAeadFromId(new Uint8Array(0));
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE AEAD identifier');
      }
    });
    it('kem param', async () => {
      try {
        HpkePrimitiveFactory.createKemFromParams(invalidHpkeParam);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KEM identifier');
      }
    });
    it('kdf param', async () => {
      try {
        HpkePrimitiveFactory.createKdfFromParams(invalidHpkeParam);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE KDF identifier');
      }
    });
    it('aead param', async () => {
      try {
        HpkePrimitiveFactory.createAeadFromParams(invalidHpkeParam);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as InvalidArgumentsException).message)
            .toBe('Unrecognized HPKE AEAD identifier');
      }
    });
  });
});
