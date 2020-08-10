/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {PbEciesAeadDemParams, PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyTemplate, PbOutputPrefixType, PbPointFormat} from '../internal/proto';

import * as HybridConfig from './hybrid_config';

/**
 * Pre-generated KeyTemplates for keys for hybrid encryption.
 *
 * One can use these templates to generate new Keyset with
 * KeysetHandle.generateNew method. To generate a new keyset that contains a
 * single EciesAeadHkdfKey, one can do:
 *
 * HybridConfig.Register();
 * KeysetHandle handle = KeysetHandle.generateNew(
 *     HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
 *
 * @final
 */
export class HybridKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of
   * EciesAeadHkdfPrivateKey with the following parameters:
   *
   *   KEM: ECDH over NIST P-256
   *   DEM: AES128-GCM
   *   KDF: HKDF-HMAC-SHA256 with an empty salt
   *   OutputPrefixType: TINK
   *
   */
  static eciesP256HkdfHmacSha256Aes128Gcm(): PbKeyTemplate {
    return createEciesAeadHkdfKeyTemplate_(
        /* curveType = */
        PbEllipticCurveType.NIST_P256,
        /* hkdfHash = */
        PbHashType.SHA256,
        /* pointFormat = */
        PbPointFormat.UNCOMPRESSED,
        /* demKeyTemplate = */
        AeadKeyTemplates.aes128Gcm(),
        /* hkdfSalt = */
        new Uint8Array(0));
  }

  /**
   * Returns a KeyTemplate that generates new instances of
   * EciesAeadHkdfPrivateKey with the following parameters:
   *
   *   KEM: ECDH over NIST P-256
   *   DEM: AES128-CTR-HMAC-SHA256 with
   *        - AES key size: 16 bytes
   *        - AES CTR IV size: 16 bytes
   *        - HMAC key size: 32 bytes
   *        - HMAC tag size: 16 bytes
   *   KDF: HKDF-HMAC-SHA256 with an empty salt
   *   OutputPrefixType: TINK
   *
   */
  static eciesP256HkdfHmacSha256Aes128CtrHmacSha256(): PbKeyTemplate {
    return createEciesAeadHkdfKeyTemplate_(
        /* curveType = */
        PbEllipticCurveType.NIST_P256,
        /* hkdfHash = */
        PbHashType.SHA256,
        /* pointFormat = */
        PbPointFormat.UNCOMPRESSED,
        /* demKeyTemplate = */
        AeadKeyTemplates.aes128CtrHmacSha256(),
        /* hkdfSalt = */
        new Uint8Array(0));
  }
}

function createEciesAeadHkdfKeyTemplate_(
    curveType: PbEllipticCurveType, hkdfHash: PbHashType,
    pointFormat: PbPointFormat, demKeyTemplate: PbKeyTemplate,
    hkdfSalt: Uint8Array): PbKeyTemplate {
  // key format
  const keyFormat =
      (new PbEciesAeadHkdfKeyFormat())
          .setParams(createEciesAeadHkdfParams_(
              curveType, hkdfHash, pointFormat, demKeyTemplate, hkdfSalt));

  // key template
  const keyTemplate =
      (new PbKeyTemplate())
          .setTypeUrl(HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE)
          .setValue(keyFormat.serializeBinary())
          .setOutputPrefixType(PbOutputPrefixType.TINK);
  return keyTemplate;
}

function createEciesAeadHkdfParams_(
    curveType: PbEllipticCurveType, hkdfHash: PbHashType,
    pointFormat: PbPointFormat, demKeyTemplate: PbKeyTemplate,
    hkdfSalt: Uint8Array): PbEciesAeadHkdfParams {
  // KEM params
  const kemParams = (new PbEciesHkdfKemParams())
                        .setCurveType(curveType)
                        .setHkdfHashType(hkdfHash)
                        .setHkdfSalt(hkdfSalt);

  // DEM params
  const demParams = (new PbEciesAeadDemParams()).setAeadDem(demKeyTemplate);

  // params
  const params = (new PbEciesAeadHkdfParams())
                     .setKemParams(kemParams)
                     .setDemParams(demParams)
                     .setEcPointFormat(pointFormat);
  return params;
}
