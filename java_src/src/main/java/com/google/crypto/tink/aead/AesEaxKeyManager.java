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
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesEaxJce;
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
 * This key manager generates new {@code AesEaxKey} keys and produces new instances of {@code
 * AesEaxJce}.
 */
public final class AesEaxKeyManager extends KeyTypeManager<AesEaxKey> {
  AesEaxKeyManager() {
    super(
        AesEaxKey.class,
        new PrimitiveFactory<Aead, AesEaxKey>(Aead.class) {
          @Override
          public Aead getPrimitive(AesEaxKey key) throws GeneralSecurityException {
            return new AesEaxJce(
                key.getKeyValue().toByteArray(), key.getParams().getIvSize());
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesEaxKey";
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
  public void validateKey(AesEaxKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    Validators.validateAesKeySize(key.getKeyValue().size());
    if (key.getParams().getIvSize() != 12 && key.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }

  @Override
  public AesEaxKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesEaxKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesEaxKeyFormat, AesEaxKey> keyFactory() {
    return new KeyFactory<AesEaxKeyFormat, AesEaxKey>(AesEaxKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesEaxKeyFormat format) throws GeneralSecurityException {
        Validators.validateAesKeySize(format.getKeySize());
        if (format.getParams().getIvSize() != 12 && format.getParams().getIvSize() != 16) {
          throw new GeneralSecurityException(
              "invalid IV size; acceptable values have 12 or 16 bytes");
        }
      }

      @Override
      public AesEaxKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesEaxKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesEaxKey createKey(AesEaxKeyFormat format) throws GeneralSecurityException {
        return AesEaxKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setParams(format.getParams())
            .setVersion(getVersion())
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<AesEaxKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<AesEaxKeyFormat>> result = new HashMap<>();
        result.put("AES128_EAX", createKeyFormat(16, 16, KeyTemplate.OutputPrefixType.TINK));
        result.put("AES128_EAX_RAW", createKeyFormat(16, 16, KeyTemplate.OutputPrefixType.RAW));

        result.put("AES256_EAX", createKeyFormat(32, 16, KeyTemplate.OutputPrefixType.TINK));
        result.put("AES256_EAX_RAW", createKeyFormat(32, 16, KeyTemplate.OutputPrefixType.RAW));

        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesEaxKeyManager(), newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate aes128EaxTemplate() {
    return createKeyTemplate(16, 16, KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   */
  public static final KeyTemplate rawAes128EaxTemplate() {
    return createKeyTemplate(16, 16, KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate aes256EaxTemplate() {
    return createKeyTemplate(32, 16, KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   */
  public static final KeyTemplate rawAes256EaxTemplate() {
    return createKeyTemplate(32, 16, KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link AesEaxKeyFormat} with some specified
   *     parameters.
   */
  private static KeyTemplate createKeyTemplate(
      int keySize, int ivSize, KeyTemplate.OutputPrefixType prefixType) {
    AesEaxKeyFormat format =
        AesEaxKeyFormat.newBuilder()
            .setKeySize(keySize)
            .setParams(AesEaxParams.newBuilder().setIvSize(ivSize).build())
            .build();
    return KeyTemplate.create(
        new AesEaxKeyManager().getKeyType(), format.toByteArray(), prefixType);
  }

  private static KeyFactory.KeyFormat<AesEaxKeyFormat> createKeyFormat(
      int keySize, int ivSize, KeyTemplate.OutputPrefixType prefixType) {
    AesEaxKeyFormat format =
        AesEaxKeyFormat.newBuilder()
            .setKeySize(keySize)
            .setParams(AesEaxParams.newBuilder().setIvSize(ivSize).build())
            .build();
    return new KeyFactory.KeyFormat<>(format, prefixType);
  }
}
