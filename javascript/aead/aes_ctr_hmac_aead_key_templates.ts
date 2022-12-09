/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbAesCtrHmacAeadKeyFormat, PbAesCtrKeyFormat, PbAesCtrParams, PbHashType, PbHmacKeyFormat, PbHmacParams, PbKeyTemplate, PbOutputPrefixType} from '../internal/proto';

import {AesCtrHmacAeadKeyManager} from './aes_ctr_hmac_aead_key_manager';

/**
 * Pre-generated KeyTemplates for AES CTR HMAC AEAD keys.
 *
 * @final
 */
export class AesCtrHmacAeadKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
   * with the following parameters:
   *    AES key size: 16 bytes
   *    AES IV size: 16 bytes
   *    HMAC key size: 32 bytes
   *    HMAC tag size: 16 bytes
   *    HMAC hash function: SHA256
   *    OutputPrefixType: TINK
   *
   */
  static aes128CtrHmacSha256(): PbKeyTemplate {
    return AesCtrHmacAeadKeyTemplates.newAesCtrHmacSha256KeyTemplate(
        /* aesKeySize = */
        16,
        /* ivSize = */
        16,
        /* hmacKeySize = */
        32,
        /* tagSize = */
        16);
  }

  /* tagSize = */
  /**
   * Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
   * with the following parameters:
   *    AES key size: 32 bytes
   *    AES IV size: 16 bytes
   *    HMAC key size: 32 bytes
   *    HMAC tag size: 32 bytes
   *    HMAC hash function: SHA256
   *    OutputPrefixType: TINK
   *
   */
  static aes256CtrHmacSha256(): PbKeyTemplate {
    return AesCtrHmacAeadKeyTemplates.newAesCtrHmacSha256KeyTemplate(
        /* aesKeySize = */
        32,
        /* ivSize = */
        16,
        /* hmacKeySize = */
        32,
        /* tagSize = */
        32);
  }

  /* tagSize = */
  private static newAesCtrHmacSha256KeyTemplate(
      aesKeySize: number, ivSize: number, hmacKeySize: number,
      tagSize: number): PbKeyTemplate {
    // Define AES CTR key format.
    const aesCtrKeyFormat = (new PbAesCtrKeyFormat())
                                .setKeySize(aesKeySize)
                                .setParams(new PbAesCtrParams());
    aesCtrKeyFormat.getParams()!.setIvSize(ivSize);

    // Define HMAC key format.
    const hmacKeyFormat = (new PbHmacKeyFormat())
                              .setKeySize(hmacKeySize)
                              .setParams(new PbHmacParams());
    hmacKeyFormat.getParams()!.setTagSize(tagSize);
    hmacKeyFormat.getParams()!.setHash(PbHashType.SHA256);

    // Define AES CTR HMAC AEAD key format.
    const keyFormat = (new PbAesCtrHmacAeadKeyFormat())
                          .setAesCtrKeyFormat(aesCtrKeyFormat)
                          .setHmacKeyFormat(hmacKeyFormat);

    // Define key template.
    const keyTemplate = (new PbKeyTemplate())
                            .setTypeUrl(AesCtrHmacAeadKeyManager.KEY_TYPE)
                            .setOutputPrefixType(PbOutputPrefixType.TINK)
                            .setValue(keyFormat.serializeBinary());
    return keyTemplate;
  }
}
