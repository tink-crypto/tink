/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeKeyFormat, PbHpkeParams, PbKeyTemplate, PbOutputPrefixType} from '../../../internal/proto';

import {HpkePrivateKeyManager} from './hpke_private_key_manager';

/**
 * Pre-generated KeyTemplates for keys for HPKE.
 *
 * One can use these templates to generate new Keyset with
 * KeysetHandle.generateNew method. To generate a new keyset that contains a
 * single HpkeKey, one can do:
 *
 * HybridConfig.Register();
 * KeysetHandle handle = KeysetHandle.generateNew(
 *     hpkeP256HkdfSha256Aes128Gcm());
 */

/**
 * Returns a KeyTemplate that generates new instances of
 * HpkePrivateKey with the following parameters:
 *
 *   KEM: DHKEM_P256_HKDF_SHA256
 *   KDF: HKDF_SHA256
 *   AEAD: AES_128_GCM
 *   OutputPrefixType: RAW
 */
export function hpkeP256HkdfSha256Aes128GcmRaw(): PbKeyTemplate {
  return createHpkeKeyTemplate(
      PbHpkeKem.DHKEM_P256_HKDF_SHA256, PbHpkeKdf.HKDF_SHA256,
      PbHpkeAead.AES_128_GCM, PbOutputPrefixType.RAW);
}
/**
 * Returns a KeyTemplate that generates new instances of
 * HpkePrivateKey with the following parameters:
 *
 *   KEM: DHKEM_P256_HKDF_SHA256
 *   KDF: HKDF_SHA256
 *   AEAD: AES_128_GCM
 *   OutputPrefixType: TINK
 */
export function hpkeP256HkdfSha256Aes128Gcm(): PbKeyTemplate {
  return createHpkeKeyTemplate(
      PbHpkeKem.DHKEM_P256_HKDF_SHA256, PbHpkeKdf.HKDF_SHA256,
      PbHpkeAead.AES_128_GCM, PbOutputPrefixType.TINK);
}
/**
 * Returns a KeyTemplate that generates new instances of
 * HpkePrivateKey with the following parameters:
 *
 *   KEM: DHKEM_P256_HKDF_SHA256
 *   KDF: HKDF_SHA256
 *   AEAD: AES_256_GCM
 *   OutputPrefixType: RAW
 */
export function hpkeP256HkdfSha256Aes256GcmRaw(): PbKeyTemplate {
  return createHpkeKeyTemplate(
      PbHpkeKem.DHKEM_P256_HKDF_SHA256, PbHpkeKdf.HKDF_SHA256,
      PbHpkeAead.AES_256_GCM, PbOutputPrefixType.RAW);
}

/**
 * Returns a KeyTemplate that generates new instances of
 * HpkePrivateKey with the following parameters:
 *
 *   KEM: DHKEM_P256_HKDF_SHA256
 *   KDF: HKDF_SHA256
 *   AEAD: AES_256_GCM
 *   OutputPrefixType: TINK
 */
export function hpkeP256HkdfSha256Aes256Gcm(): PbKeyTemplate {
  return createHpkeKeyTemplate(
      PbHpkeKem.DHKEM_P256_HKDF_SHA256, PbHpkeKdf.HKDF_SHA256,
      PbHpkeAead.AES_256_GCM, PbOutputPrefixType.TINK);
}

/**
 * Returns a KeyTemplate that generates new instances of
 * HpkePrivateKey with the following parameters:
 *
 *   KEM: DHKEM_P521_HKDF_SHA512
 *   KDF: HKDF_SHA256
 *   AEAD: AES_256_GCM
 *   OutputPrefixType: RAW
 */
export function hpkeP521HkdfSha512Aes256GcmRaw(): PbKeyTemplate {
  return createHpkeKeyTemplate(
      PbHpkeKem.DHKEM_P521_HKDF_SHA512, PbHpkeKdf.HKDF_SHA512,
      PbHpkeAead.AES_256_GCM, PbOutputPrefixType.RAW);
}

/**
 * Returns a KeyTemplate that generates new instances of
 * HpkePrivateKey with the following parameters:
 *
 *   KEM: DHKEM_P521_HKDF_SHA512
 *   KDF: HKDF_SHA256
 *   AEAD: AES_256_GCM
 *   OutputPrefixType: TINK
 */
export function hpkeP521HkdfSha512Aes256Gcm(): PbKeyTemplate {
  return createHpkeKeyTemplate(
      PbHpkeKem.DHKEM_P521_HKDF_SHA512, PbHpkeKdf.HKDF_SHA512,
      PbHpkeAead.AES_256_GCM, PbOutputPrefixType.TINK);
}

function createHpkeKeyTemplate(
    kem: PbHpkeKem, kdf: PbHpkeKdf, aead: PbHpkeAead,
    outputPrefix: PbOutputPrefixType): PbKeyTemplate {
  // key format
  const keyFormat =
      (new PbHpkeKeyFormat())
          .setParams(new PbHpkeParams().setKem(kem).setKdf(kdf).setAead(aead));

  // key template
  const keyTemplate = (new PbKeyTemplate())
                          .setTypeUrl(HpkePrivateKeyManager.KEY_TYPE)
                          .setValue(keyFormat.serializeBinary())
                          .setOutputPrefixType(outputPrefix);
  return keyTemplate;
}
