// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Helper generating {@code Aead}-instances for specified {@code KeyTemplate} and key material. It
 * uses selected {@code KeyManager}-instances from the {@code Registry} to obtain the instances of
 * {@code Aead}.
 */
class RegistryEciesAeadHkdfDemHelper implements EciesAeadHkdfDemHelper {
  private final String demKeyTypeUrl;
  private final int symmetricKeySize;

  // used iff demKeyTypeUrl == AeadConfig.AES_GCM_TYPE_URL
  private AesGcmKey aesGcmKey;

  // used iff demKeyTypeUrl == AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL
  private AesCtrHmacAeadKey aesCtrHmacAeadKey;
  private int aesCtrKeySize;

  RegistryEciesAeadHkdfDemHelper(KeyTemplate demTemplate) throws GeneralSecurityException {
    demKeyTypeUrl = demTemplate.getTypeUrl();
    if (demKeyTypeUrl.equals(AeadConfig.AES_GCM_TYPE_URL)) {
      try {
        AesGcmKeyFormat gcmKeyFormat = AesGcmKeyFormat.parseFrom(demTemplate.getValue());
        this.aesGcmKey = (AesGcmKey) Registry.newKey(demTemplate);
        this.symmetricKeySize = gcmKeyFormat.getKeySize();
      } catch (InvalidProtocolBufferException e) {
        throw new GeneralSecurityException(
            "invalid KeyFormat protobuf, expected AesGcmKeyFormat", e);
      }
    } else if (demKeyTypeUrl.equals(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)) {
      try {
        AesCtrHmacAeadKeyFormat aesCtrHmacAeadKeyFormat =
            AesCtrHmacAeadKeyFormat.parseFrom(demTemplate.getValue());
        this.aesCtrHmacAeadKey = (AesCtrHmacAeadKey) Registry.newKey(demTemplate);
        this.aesCtrKeySize = aesCtrHmacAeadKeyFormat.getAesCtrKeyFormat().getKeySize();
        int hmacKeySize = aesCtrHmacAeadKeyFormat.getHmacKeyFormat().getKeySize();
        this.symmetricKeySize = aesCtrKeySize + hmacKeySize;
      } catch (InvalidProtocolBufferException e) {
        throw new GeneralSecurityException(
            "invalid KeyFormat protobuf, expected AesCtrHmacAeadKeyFormat", e);
      }
    } else {
      throw new GeneralSecurityException("unsupported AEAD DEM key type: " + demKeyTypeUrl);
    }
  }

  @Override
  public int getSymmetricKeySizeInBytes() {
    return symmetricKeySize;
  }

  @Override
  public Aead getAead(final byte[] symmetricKeyValue) throws GeneralSecurityException {
    if (symmetricKeyValue.length != getSymmetricKeySizeInBytes()) {
      throw new GeneralSecurityException("Symmetric key has incorrect length");
    }
    if (demKeyTypeUrl.equals(AeadConfig.AES_GCM_TYPE_URL)) {
      AesGcmKey aeadKey = AesGcmKey.newBuilder()
          .mergeFrom(aesGcmKey)
          .setKeyValue(ByteString.copyFrom(symmetricKeyValue, 0, symmetricKeySize))
          .build();
      return Registry.getPrimitive(demKeyTypeUrl, aeadKey, Aead.class);
    } else if (demKeyTypeUrl.equals(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)) {
      byte[] aesCtrKeyValue = Arrays.copyOfRange(symmetricKeyValue, 0, aesCtrKeySize);
      byte[] hmacKeyValue = Arrays.copyOfRange(symmetricKeyValue, aesCtrKeySize, symmetricKeySize);
      AesCtrKey aesCtrKey =
          AesCtrKey.newBuilder()
              .mergeFrom(aesCtrHmacAeadKey.getAesCtrKey())
              .setKeyValue(ByteString.copyFrom(aesCtrKeyValue))
              .build();
      HmacKey hmacKey =
          HmacKey.newBuilder()
              .mergeFrom(aesCtrHmacAeadKey.getHmacKey())
              .setKeyValue(ByteString.copyFrom(hmacKeyValue))
              .build();
      AesCtrHmacAeadKey aeadKey =
          AesCtrHmacAeadKey.newBuilder()
              .setVersion(aesCtrHmacAeadKey.getVersion())
              .setAesCtrKey(aesCtrKey)
              .setHmacKey(hmacKey)
              .build();
      return Registry.getPrimitive(demKeyTypeUrl, aeadKey, Aead.class);
    } else {
      throw new GeneralSecurityException("unknown DEM key type");
    }
  }
}
