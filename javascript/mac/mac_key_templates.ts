/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbHashType, PbHmacKeyFormat, PbHmacParams, PbKeyTemplate, PbOutputPrefixType} from '../internal/proto';

import {HmacKeyManager} from './hmac_key_manager';

/**
 * Pre-generated KeyTemplates for HMAC keys.
 *
 * These templates can be used to generate a new Keyset with the
 * KeysetHandle.generateNew method. A new keyset containing a single
 * HmacKey can be generated with the following code snippet:
 *
 * MacConfig.Register();
 * KeysetHandle handle = KeysetHandle.generateNew(hmacSha256Tag128());
 */

/**
 * Returns a KeyTemplate that generates new instances of
 * HmacKey with the following parameters:
 *
 *   Key size: 32 bytes
 *   Tag size: 16 bytes
 *   Hash function: SHA-256
 *   OutputPrefixType: TINK
 */
export function hmacSha256Tag128(): PbKeyTemplate {
  return createHmacKeyTemplate(
      /* keySize = */ 32, /* tagSize = */ 16, PbHashType.SHA256);
}

/**
 * Returns a KeyTemplate that generates new instances of
 * HmacKey with the following parameters:
 *
 *   Key size: 32 bytes
 *   Tag size: 32 bytes
 *   Hash function: SHA-256
 *   OutputPrefixType: TINK
 */
export function hmacSha256Tag256(): PbKeyTemplate {
  return createHmacKeyTemplate(
      /* keySize = */ 32, /* tagSize = */ 32, PbHashType.SHA256);
}

/**
 * Returns a KeyTemplate that generates new instances of
 * HmacKey with the following parameters:
 *
 *   Key size: 64 bytes
 *   Tag size: 32 bytes
 *   Hash function: SHA-512
 *   OutputPrefixType: TINK
 */
export function hmacSha512Tag256(): PbKeyTemplate {
  return createHmacKeyTemplate(
      /* keySize = */ 64, /* tagSize = */ 32, PbHashType.SHA512);
}

/**
 * Returns a KeyTemplate that generates new instances of
 * HmacKey with the following parameters:
 *
 *   Key size: 64 bytes
 *   Tag size: 64 bytes
 *   Hash function: SHA-512
 *   OutputPrefixType: TINK
 */
export function hmacSha512Tag512(): PbKeyTemplate {
  return createHmacKeyTemplate(
      /* keySize = */ 64, /* tagSize = */ 64, PbHashType.SHA512);
}

function createHmacKeyTemplate(
    keySize: number, tagSize: number, hashType: PbHashType): PbKeyTemplate {
  const params = new PbHmacParams().setTagSize(tagSize).setHash(hashType);
  const keyFormat = new PbHmacKeyFormat().setParams(params).setKeySize(keySize);

  return new PbKeyTemplate()
      .setTypeUrl(HmacKeyManager.KEY_TYPE)
      .setOutputPrefixType(PbOutputPrefixType.TINK)
      .setValue(keyFormat.serializeBinary());
}
