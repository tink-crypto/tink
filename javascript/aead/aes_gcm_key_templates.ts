/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbAesGcmKeyFormat, PbKeyTemplate, PbOutputPrefixType} from '../internal/proto';

import {AesGcmKeyManager} from './aes_gcm_key_manager';

/**
 * Pre-generated KeyTemplates for AES GCM keys.
 *
 * @final
 */
export class AesGcmKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 16 bytes
   *    OutputPrefixType: TINK
   *
   */
  static aes128Gcm(): PbKeyTemplate {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate(
        /* keySize = */
        16,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 32 bytes
   *    OutputPrefixType: TINK
   *
   */
  static aes256Gcm(): PbKeyTemplate {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate(
        /* keySize = */
        32,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *     key size: 32 bytes
   *     OutputPrefixType: RAW
   *
   */
  static aes256GcmNoPrefix(): PbKeyTemplate {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate(
        /* keySize = */
        32,
        /* outputPrefixType = */
        PbOutputPrefixType.RAW);
  }

  private static newAesGcmKeyTemplate(
      keySize: number, outputPrefixType: PbOutputPrefixType): PbKeyTemplate {
    // Define AES GCM key format.
    const keyFormat = (new PbAesGcmKeyFormat()).setKeySize(keySize);

    // Define key template.
    const keyTemplate = (new PbKeyTemplate())
                            .setTypeUrl(AesGcmKeyManager.KEY_TYPE)
                            .setOutputPrefixType(outputPrefixType)
                            .setValue(keyFormat.serializeBinary());
    return keyTemplate;
  }
}
