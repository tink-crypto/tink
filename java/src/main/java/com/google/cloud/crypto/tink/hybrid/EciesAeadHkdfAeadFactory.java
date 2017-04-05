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

package com.google.cloud.crypto.tink.hybrid; // instead of subtle, because it depends on Tink-protos.

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKey;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKeyFormat;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKey;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKey;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKeyFormat;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Helper generating {@code Aead}-instances for specified {@code KeyTemplate} and key material.
 */
final class EciesAeadHkdfAeadFactory {
  private static final String AES_GCM_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";

  private static final String AES_CTR_HMAC_AEAD_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey";

  private enum DemKeyType {
    AES_GCM_KEY,
    AES_CTR_HMAC_AEAD_KEY
  }

  private final DemKeyType demKeyType;
  private final int symmetricKeySize;

  // used iff demKeyType == AES_GCM_KEY
  private AesGcmKey aesGcmKey;

  // used iff demKeyType == AES_CTR_HMAC_AEAD_KEY
  private AesCtrHmacAeadKey aesCtrHmacAeadKey;
  private int aesCtrKeySize;

  public EciesAeadHkdfAeadFactory(KeyTemplate demTemplate) throws GeneralSecurityException {
    String keyType = demTemplate.getTypeUrl();
    if (keyType.equals(AES_GCM_KEY_TYPE)) {
      try {
        AesGcmKeyFormat gcmKeyFormat = AesGcmKeyFormat.parseFrom(demTemplate.getValue());
        this.demKeyType = DemKeyType.AES_GCM_KEY;
        this.aesGcmKey = Registry.INSTANCE.newKey(demTemplate);
        this.symmetricKeySize = gcmKeyFormat.getKeySize();
      } catch (InvalidProtocolBufferException e) {
        throw new GeneralSecurityException(
            "invalid KeyFormat protobuf, expected AesGcmKeyFormat", e);
      }
    } else if (keyType.equals(AES_CTR_HMAC_AEAD_KEY_TYPE)) {
      try {
        AesCtrHmacAeadKeyFormat aesCtrHmacAeadKeyFormat = AesCtrHmacAeadKeyFormat.parseFrom(
            demTemplate.getValue());
        this.demKeyType = DemKeyType.AES_CTR_HMAC_AEAD_KEY;
        this.aesCtrHmacAeadKey = Registry.INSTANCE.newKey(demTemplate);
        this.aesCtrKeySize = aesCtrHmacAeadKeyFormat.getAesCtrKeyFormat().getKeySize();
        int hmacKeySize = aesCtrHmacAeadKeyFormat.getHmacKeyFormat().getKeySize();
        this.symmetricKeySize = aesCtrKeySize + hmacKeySize;
      } catch (InvalidProtocolBufferException e) {
        throw new GeneralSecurityException(
            "invalid KeyFormat protobuf, expected AesGcmKeyFormat", e);
      }
    } else {
      throw new GeneralSecurityException("unsupported AEAD DEM key type: " + keyType);
    }
  }

  public int getSymmetricKeySize() {
    return symmetricKeySize;
  }

  public Aead getAead(final byte[] symmetricKeyValue) throws GeneralSecurityException {
    if (demKeyType == DemKeyType.AES_GCM_KEY) {
      AesGcmKey aeadKey = AesGcmKey.newBuilder()
          .mergeFrom(aesGcmKey)
          .setKeyValue(ByteString.copyFrom(symmetricKeyValue))
          .build();
      return Registry.INSTANCE.getPrimitive(AES_GCM_KEY_TYPE, aeadKey);
    } else if (demKeyType == DemKeyType.AES_CTR_HMAC_AEAD_KEY) {
      byte[] aesCtrKeyValue = Arrays.copyOfRange(symmetricKeyValue, 0, aesCtrKeySize);
      byte[] hmacKeyValue = Arrays.copyOfRange(symmetricKeyValue, aesCtrKeySize, symmetricKeySize);
      AesCtrKey aesCtrKey = AesCtrKey.newBuilder()
          .mergeFrom(aesCtrHmacAeadKey.getAesCtrKey())
          .setKeyValue(ByteString.copyFrom(aesCtrKeyValue)).build();
      HmacKey hmacKey = HmacKey.newBuilder()
          .mergeFrom(aesCtrHmacAeadKey.getHmacKey())
          .setKeyValue(ByteString.copyFrom(hmacKeyValue)).build();
      AesCtrHmacAeadKey aeadKey = AesCtrHmacAeadKey.newBuilder()
          .setVersion(aesCtrHmacAeadKey.getVersion())
          .setAesCtrKey(aesCtrKey)
          .setHmacKey(hmacKey)
          .build();
      return Registry.INSTANCE.getPrimitive(AES_CTR_HMAC_AEAD_KEY_TYPE, aeadKey);
    } else {
      throw new GeneralSecurityException("unknown DEM key type");
    }
  }
}
