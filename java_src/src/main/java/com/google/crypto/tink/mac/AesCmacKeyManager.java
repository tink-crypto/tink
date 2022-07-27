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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.proto.AesCmacKey;
import com.google.crypto.tink.proto.AesCmacKeyFormat;
import com.google.crypto.tink.proto.AesCmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code AesCmacKey} keys and produces new instances of {@code
 * AesCmac}.
 */
public final class AesCmacKeyManager extends KeyTypeManager<AesCmacKey> {
  AesCmacKeyManager() {
    super(
        AesCmacKey.class,
        new PrimitiveFactory<Mac, AesCmacKey>(Mac.class) {
          @Override
          public Mac getPrimitive(AesCmacKey key) throws GeneralSecurityException {
            return new PrfMac(
                new PrfAesCmac(key.getKeyValue().toByteArray()), key.getParams().getTagSize());
          }
        });
  }

  private static final int VERSION = 0;
  private static final int KEY_SIZE_IN_BYTES = 32;
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;
  private static final int MAX_TAG_SIZE_IN_BYTES = 16;

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCmacKey";
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(AesCmacKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    validateSize(key.getKeyValue().size());
    validateParams(key.getParams());
  }

  @Override
  public AesCmacKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesCmacKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  private static void validateParams(AesCmacParams params) throws GeneralSecurityException {
    if (params.getTagSize() < MIN_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("tag size too short");
    }
    if (params.getTagSize() > MAX_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("tag size too long");
    }
  }

  private static void validateSize(int size) throws GeneralSecurityException {
    if (size != KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("AesCmacKey size wrong, must be 32 bytes");
    }
  }

  @Override
  public KeyFactory<AesCmacKeyFormat, AesCmacKey> keyFactory() {
    return new KeyFactory<AesCmacKeyFormat, AesCmacKey>(AesCmacKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesCmacKeyFormat format) throws GeneralSecurityException {
        validateParams(format.getParams());
        validateSize(format.getKeySize());
      }

      @Override
      public AesCmacKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesCmacKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesCmacKey createKey(AesCmacKeyFormat format) throws GeneralSecurityException {
        return AesCmacKey.newBuilder()
            .setVersion(VERSION)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setParams(format.getParams())
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<AesCmacKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<AesCmacKeyFormat>> result = new HashMap<>();
        result.put(
            "AES_CMAC", // backward compatibility with MacKeyTemplates
            new KeyFactory.KeyFormat<>(
                AesCmacKeyFormat.newBuilder()
                    .setKeySize(32)
                    .setParams(AesCmacParams.newBuilder().setTagSize(16).build())
                    .build(),
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "AES256_CMAC",
            new KeyFactory.KeyFormat<>(
                AesCmacKeyFormat.newBuilder()
                    .setKeySize(32)
                    .setParams(AesCmacParams.newBuilder().setTagSize(16).build())
                    .build(),
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "AES256_CMAC_RAW",
            new KeyFactory.KeyFormat<>(
                AesCmacKeyFormat.newBuilder()
                    .setKeySize(32)
                    .setParams(AesCmacParams.newBuilder().setTagSize(16).build())
                    .build(),
                KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesCmacKeyManager(), newKeyAllowed);
    AesCmacProtoSerialization.register();
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Tag size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("AES256_CMAC")}
   */
  @Deprecated
  public static final KeyTemplate aes256CmacTemplate() {
    AesCmacKeyFormat format =
        AesCmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(AesCmacParams.newBuilder().setTagSize(16).build())
            .build();
    return KeyTemplate.create(
        new AesCmacKeyManager().getKeyType(),
        format.toByteArray(),
        KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Tag size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("AES256_CMAC_RAW")}
   */
  @Deprecated
  public static final KeyTemplate rawAes256CmacTemplate() {
    AesCmacKeyFormat format =
        AesCmacKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(AesCmacParams.newBuilder().setTagSize(16).build())
            .build();
    return KeyTemplate.create(
        new AesCmacKeyManager().getKeyType(),
        format.toByteArray(),
        KeyTemplate.OutputPrefixType.RAW);
  }
}
