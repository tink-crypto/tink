/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead';
import {AeadConfig} from '../aead/aead_config';
import {SecurityException} from '../exception/security_exception';
import {PbAesCtrHmacAeadKey, PbAesCtrHmacAeadKeyFormat, PbAesGcmKey, PbAesGcmKeyFormat, PbKeyTemplate} from '../internal/proto';
import * as Registry from '../internal/registry';
import {EciesAeadHkdfDemHelper} from '../subtle/ecies_aead_hkdf_dem_helper';

/**
 * @final
 */
export class RegistryEciesAeadHkdfDemHelper implements EciesAeadHkdfDemHelper {
  private readonly key: PbAesCtrHmacAeadKey|PbAesGcmKey;
  private readonly demKeyTypeUrl: string;
  private readonly demKeySize: number;
  private readonly aesCtrKeySize?: number;

  constructor(keyTemplate: PbKeyTemplate) {
    let demKeySize: number;
    let aesCtrKeySize: number|undefined;
    let keyFormat: PbAesCtrHmacAeadKeyFormat|PbAesGcmKeyFormat;
    const keyTypeUrl = keyTemplate.getTypeUrl();
    switch (keyTypeUrl) {
      case AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL:
        keyFormat =
            RegistryEciesAeadHkdfDemHelper.getAesCtrHmacKeyFormat(keyTemplate);
        const aesCtrKeyFormat = keyFormat.getAesCtrKeyFormat();
        if (!aesCtrKeyFormat) {
          throw new SecurityException('AES-CTR key format not set');
        }
        aesCtrKeySize = aesCtrKeyFormat.getKeySize();
        const hmacKeyFormat = keyFormat.getHmacKeyFormat();
        if (!hmacKeyFormat) {
          throw new SecurityException('HMAC key format not set');
        }
        const hmacKeySize = hmacKeyFormat.getKeySize();
        demKeySize = aesCtrKeySize + hmacKeySize;
        break;
      case AeadConfig.AES_GCM_TYPE_URL:
        keyFormat =
            RegistryEciesAeadHkdfDemHelper.getAesGcmKeyFormat(keyTemplate);
        demKeySize = keyFormat.getKeySize();
        break;
      default:
        throw new SecurityException(
            'Key type URL ' + keyTypeUrl + ' is not supported.');
    }
    const keyFactory = Registry.getKeyManager(keyTypeUrl).getKeyFactory();
    this.key =
        (keyFactory.newKey(keyFormat) as PbAesCtrHmacAeadKey | PbAesGcmKey);
    this.demKeyTypeUrl = keyTypeUrl;
    this.demKeySize = demKeySize;
    this.aesCtrKeySize = aesCtrKeySize;
  }

  /**
   */
  getDemKeySizeInBytes() {
    return this.demKeySize;
  }

  /**
   */
  async getAead(demKey: Uint8Array): Promise<Aead> {
    if (demKey.length !== this.demKeySize) {
      throw new SecurityException(
          `Key is not of the correct length, expected length: ${
              this.demKeySize}, but got key of length: ${demKey.length}.`);
    }
    let key: PbAesCtrHmacAeadKey|PbAesGcmKey;
    if (this.demKeyTypeUrl === AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL) {
      key = this.replaceAesCtrHmacKeyValue(demKey);
    } else {
      key = this.replaceAesGcmKeyValue(demKey);
    }
    return Registry.getPrimitive<Aead>(Aead, key, this.demKeyTypeUrl);
  }

  private static getAesGcmKeyFormat(keyTemplate: PbKeyTemplate):
      PbAesGcmKeyFormat {
    let keyFormat: PbAesGcmKeyFormat;
    try {
      keyFormat = PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue());
    } catch (e) {
      throw new SecurityException(
          'Could not parse the given Uint8Array as a serialized proto of ' +
          AeadConfig.AES_GCM_TYPE_URL + '.');
    }
    if (!keyFormat.getKeySize()) {
      throw new SecurityException(
          'Could not parse the given Uint8Array as a serialized proto of ' +
          AeadConfig.AES_GCM_TYPE_URL + '.');
    }
    return keyFormat;
  }

  private static getAesCtrHmacKeyFormat(keyTemplate: PbKeyTemplate):
      PbAesCtrHmacAeadKeyFormat {
    let keyFormat: PbAesCtrHmacAeadKeyFormat;
    try {
      keyFormat =
          PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyTemplate.getValue());
    } catch (e) {
      throw new SecurityException(
          'Could not parse the given Uint8Array ' +
          'as a serialized proto of ' + AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL +
          '.');
    }
    if (!keyFormat.getAesCtrKeyFormat() || !keyFormat.getHmacKeyFormat()) {
      throw new SecurityException(
          'Could not parse the given Uint8Array as a serialized proto of ' +
          AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL + '.');
    }
    return keyFormat;
  }

  private replaceAesGcmKeyValue(symmetricKey: Uint8Array): PbAesGcmKey {
    if (!(this.key instanceof PbAesGcmKey)) {
      throw new SecurityException('Key is not an AES-CTR key');
    }
    const key = this.key.setKeyValue(symmetricKey);
    return key;
  }

  private replaceAesCtrHmacKeyValue(symmetricKey: Uint8Array):
      PbAesCtrHmacAeadKey {
    const key = (this.key as PbAesCtrHmacAeadKey);
    const aesCtrKey = key.getAesCtrKey();
    if (!aesCtrKey) {
      throw new SecurityException('AES-CTR key not set');
    }
    const aesCtrKeyValue = symmetricKey.slice(0, this.aesCtrKeySize);
    aesCtrKey.setKeyValue(aesCtrKeyValue);
    const hmacKey = key.getHmacKey();
    if (!hmacKey) {
      throw new SecurityException('HMAC key not set');
    }
    const hmacKeyValue =
        symmetricKey.slice(this.aesCtrKeySize, this.demKeySize);
    hmacKey.setKeyValue(hmacKeyValue);
    return key;
  }
}
