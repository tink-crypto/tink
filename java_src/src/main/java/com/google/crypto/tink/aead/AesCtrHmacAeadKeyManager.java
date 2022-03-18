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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.IndCpaCipher;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@link AesCtrHmacAeadKey} keys and produces new instances of
 * {@link EncryptThenAuthenticate}.
 */
public final class AesCtrHmacAeadKeyManager extends KeyTypeManager<AesCtrHmacAeadKey> {
  AesCtrHmacAeadKeyManager() {
    super(
        AesCtrHmacAeadKey.class,
        new PrimitiveFactory<Aead, AesCtrHmacAeadKey>(Aead.class) {
          @Override
          public Aead getPrimitive(AesCtrHmacAeadKey key) throws GeneralSecurityException {
            return new EncryptThenAuthenticate(
                new AesCtrKeyManager().getPrimitive(key.getAesCtrKey(), IndCpaCipher.class),
                new HmacKeyManager().getPrimitive(key.getHmacKey(), Mac.class),
                key.getHmacKey().getParams().getTagSize());
          }
        });
  }

  // Static so we don't have to construct the object and handle the exception when we need the
  // key type.
  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    new AesCtrKeyManager().validateKey(key.getAesCtrKey());
    new HmacKeyManager().validateKey(key.getHmacKey());
  }

  @Override
  public AesCtrHmacAeadKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesCtrHmacAeadKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesCtrHmacAeadKeyFormat, AesCtrHmacAeadKey> keyFactory() {
    return new KeyFactory<AesCtrHmacAeadKeyFormat, AesCtrHmacAeadKey>(
        AesCtrHmacAeadKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesCtrHmacAeadKeyFormat format)
          throws GeneralSecurityException {
        new AesCtrKeyManager().keyFactory().validateKeyFormat(format.getAesCtrKeyFormat());
        new HmacKeyManager().keyFactory().validateKeyFormat(format.getHmacKeyFormat());
        Validators.validateAesKeySize(format.getAesCtrKeyFormat().getKeySize());
      }

      @Override
      public AesCtrHmacAeadKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesCtrHmacAeadKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesCtrHmacAeadKey createKey(AesCtrHmacAeadKeyFormat format)
          throws GeneralSecurityException {
        AesCtrKey aesCtrKey =
            new AesCtrKeyManager().keyFactory().createKey(format.getAesCtrKeyFormat());
        HmacKey hmacKey = new HmacKeyManager().keyFactory().createKey(format.getHmacKeyFormat());
        return AesCtrHmacAeadKey.newBuilder()
            .setAesCtrKey(aesCtrKey)
            .setHmacKey(hmacKey)
            .setVersion(getVersion())
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<AesCtrHmacAeadKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<AesCtrHmacAeadKeyFormat>> result = new HashMap<>();

        result.put(
            "AES128_CTR_HMAC_SHA256",
            createKeyFormat(16, 16, 32, 16, HashType.SHA256, KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "AES128_CTR_HMAC_SHA256_RAW",
            createKeyFormat(16, 16, 32, 16, HashType.SHA256, KeyTemplate.OutputPrefixType.RAW));

        result.put(
            "AES256_CTR_HMAC_SHA256",
            createKeyFormat(32, 16, 32, 32, HashType.SHA256, KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "AES256_CTR_HMAC_SHA256_RAW",
            createKeyFormat(32, 16, 32, 32, HashType.SHA256, KeyTemplate.OutputPrefixType.RAW));

        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesCtrHmacAeadKeyManager(), newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-CTR-HMAC-AEAD keys with the
   *     following parameters:
   *     <ul>
   *       <li>AES key size: 16 bytes
   *       <li>AES CTR IV size: 16 byte
   *       <li>HMAC key size: 32 bytes
   *       <li>HMAC tag size: 16 bytes
   *       <li>HMAC hash function: SHA256
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("AES128_CTR_HMAC_SHA256")}
   */
  @Deprecated
  public static final KeyTemplate aes128CtrHmacSha256Template() {
    return createKeyTemplate(16, 16, 32, 16, HashType.SHA256);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-CTR-HMAC-AEAD keys with the
   *     following parameters:
   *     <ul>
   *       <li>AES key size: 32 bytes
   *       <li>AES CTR IV size: 16 byte
   *       <li>HMAC key size: 32 bytes
   *       <li>HMAC tag size: 32 bytes
   *       <li>HMAC hash function: SHA256
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("AES256_CTR_HMAC_SHA256")}
   */
  @Deprecated
  public static final KeyTemplate aes256CtrHmacSha256Template() {
    return createKeyTemplate(32, 16, 32, 32, HashType.SHA256);
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link AesCtrHmacAeadKeyFormat} with some specific
   *     parameters.
   */
  private static KeyTemplate createKeyTemplate(
      int aesKeySize, int ivSize, int hmacKeySize, int tagSize, HashType hashType) {
    AesCtrHmacAeadKeyFormat format =
        createKeyFormat(aesKeySize, ivSize, hmacKeySize, tagSize, hashType);
    return KeyTemplate.create(
        new AesCtrHmacAeadKeyManager().getKeyType(),
        format.toByteArray(),
        KeyTemplate.OutputPrefixType.TINK);
  }

  private static KeyFactory.KeyFormat<AesCtrHmacAeadKeyFormat> createKeyFormat(
      int aesKeySize,
      int ivSize,
      int hmacKeySize,
      int tagSize,
      HashType hashType,
      KeyTemplate.OutputPrefixType prefixType) {
    return new KeyFactory.KeyFormat<>(
        createKeyFormat(aesKeySize, ivSize, hmacKeySize, tagSize, hashType), prefixType);
  }

  private static AesCtrHmacAeadKeyFormat createKeyFormat(
      int aesKeySize, int ivSize, int hmacKeySize, int tagSize, HashType hashType) {
    AesCtrKeyFormat aesCtrKeyFormat =
        AesCtrKeyFormat.newBuilder()
            .setParams(AesCtrParams.newBuilder().setIvSize(ivSize).build())
            .setKeySize(aesKeySize)
            .build();
    HmacKeyFormat hmacKeyFormat =
        HmacKeyFormat.newBuilder()
            .setParams(HmacParams.newBuilder().setHash(hashType).setTagSize(tagSize).build())
            .setKeySize(hmacKeySize)
            .build();
    return AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(aesCtrKeyFormat)
        .setHmacKeyFormat(hmacKeyFormat)
        .build();
  }

  @Override
  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
  };
}
