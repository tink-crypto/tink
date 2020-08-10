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
  private readonly key_: PbAesCtrHmacAeadKey|PbAesGcmKey;
  private readonly demKeyTypeUrl_: string;
  private readonly demKeySize_: number;
  private readonly aesCtrKeySize_?: number;

  constructor(keyTemplate: PbKeyTemplate) {
    let demKeySize: number;
    let aesCtrKeySize: number|undefined;
    let keyFormat: PbAesCtrHmacAeadKeyFormat|PbAesGcmKeyFormat;
    const keyTypeUrl = keyTemplate.getTypeUrl();
    switch (keyTypeUrl) {
      case AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL:
        keyFormat =
            RegistryEciesAeadHkdfDemHelper.getAesCtrHmacKeyFormat_(keyTemplate);
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
            RegistryEciesAeadHkdfDemHelper.getAesGcmKeyFormat_(keyTemplate);
        demKeySize = keyFormat.getKeySize();
        break;
      default:
        throw new SecurityException(
            'Key type URL ' + keyTypeUrl + ' is not supported.');
    }
    const keyFactory = Registry.getKeyManager(keyTypeUrl).getKeyFactory();
    this.key_ =
        (keyFactory.newKey(keyFormat) as PbAesCtrHmacAeadKey | PbAesGcmKey);
    this.demKeyTypeUrl_ = keyTypeUrl;
    this.demKeySize_ = demKeySize;
    this.aesCtrKeySize_ = aesCtrKeySize;
  }

  /**
   * @override
   */
  getDemKeySizeInBytes() {
    return this.demKeySize_;
  }

  /**
   * @override
   */
  async getAead(demKey: Uint8Array): Promise<Aead> {
    if (demKey.length != this.demKeySize_) {
      throw new SecurityException(
          'Key is not of the correct length, expected length: ' +
          this.demKeySize_ + ', but got key of length: ' + demKey.length + '.');
    }
    let key: PbAesCtrHmacAeadKey|PbAesGcmKey;
    if (this.demKeyTypeUrl_ === AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL) {
      key = this.replaceAesCtrHmacKeyValue_(demKey);
    } else {
      key = this.replaceAesGcmKeyValue_(demKey);
    }
    return Registry.getPrimitive<Aead>(Aead, key, this.demKeyTypeUrl_);
  }

  private static getAesGcmKeyFormat_(keyTemplate: PbKeyTemplate):
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

  private static getAesCtrHmacKeyFormat_(keyTemplate: PbKeyTemplate):
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

  private replaceAesGcmKeyValue_(symmetricKey: Uint8Array): PbAesGcmKey {
    if (!(this.key_ instanceof PbAesGcmKey)) {
      throw new SecurityException('Key is not an AES-CTR key');
    }
    const key = this.key_.setKeyValue(symmetricKey);
    return key;
  }

  private replaceAesCtrHmacKeyValue_(symmetricKey: Uint8Array):
      PbAesCtrHmacAeadKey {
    const key = (this.key_ as PbAesCtrHmacAeadKey);
    const aesCtrKey = key.getAesCtrKey();
    if (!aesCtrKey) {
      throw new SecurityException('AES-CTR key not set');
    }
    const aesCtrKeyValue = symmetricKey.slice(0, this.aesCtrKeySize_);
    aesCtrKey.setKeyValue(aesCtrKeyValue);
    const hmacKey = key.getHmacKey();
    if (!hmacKey) {
      throw new SecurityException('HMAC key not set');
    }
    const hmacKeyValue =
        symmetricKey.slice(this.aesCtrKeySize_, this.demKeySize_);
    hmacKey.setKeyValue(hmacKeyValue);
    return key;
  }
}
