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
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.AesGcmSivKey;
import com.google.crypto.tink.proto.AesGcmSivKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * This key manager generates new {@code AesGcmSivKey} keys and produces new instances of {@code
 * AesGcmSiv}.
 */
public final class AesGcmSivKeyManager extends KeyTypeManager<AesGcmSivKey> {
  AesGcmSivKeyManager() {
    super(
        AesGcmSivKey.class,
        new PrimitiveFactory<Aead, AesGcmSivKey>(Aead.class) {
          @Override
          public Aead getPrimitive(AesGcmSivKey key) throws GeneralSecurityException {
            return new AesGcmSiv(key.getKeyValue().toByteArray());
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesGcmSivKey";
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
  public void validateKey(AesGcmSivKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    Validators.validateAesKeySize(key.getKeyValue().size());
  }

  @Override
  public AesGcmSivKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesGcmSivKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesGcmSivKeyFormat, AesGcmSivKey> keyFactory() {
    return new KeyFactory<AesGcmSivKeyFormat, AesGcmSivKey>(AesGcmSivKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesGcmSivKeyFormat format) throws GeneralSecurityException {
        Validators.validateAesKeySize(format.getKeySize());
      }

      @Override
      public AesGcmSivKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesGcmSivKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesGcmSivKey createKey(AesGcmSivKeyFormat format) {
        return AesGcmSivKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setVersion(getVersion())
            .build();
      }

      @Override
      public AesGcmSivKey deriveKey(AesGcmSivKeyFormat format, InputStream inputStream)
          throws GeneralSecurityException {
        Validators.validateVersion(format.getVersion(), getVersion());

        byte[] pseudorandomness = new byte[format.getKeySize()];
        try {
          int read = inputStream.read(pseudorandomness);
          if (read != format.getKeySize()) {
            throw new GeneralSecurityException("Not enough pseudorandomness given");
          }
          return AesGcmSivKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(pseudorandomness))
              .setVersion(getVersion())
              .build();
        } catch (IOException e) {
          throw new GeneralSecurityException("Reading pseudorandomness failed", e);
        }
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<AesGcmSivKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<AesGcmSivKeyFormat>> result = new HashMap<>();

        result.put("AES128_GCM_SIV", createKeyFormat(16, KeyTemplate.OutputPrefixType.TINK));
        result.put("AES128_GCM_SIV_RAW", createKeyFormat(16, KeyTemplate.OutputPrefixType.RAW));

        result.put("AES256_GCM_SIV", createKeyFormat(32, KeyTemplate.OutputPrefixType.TINK));
        result.put("AES256_GCM_SIV_RAW", createKeyFormat(32, KeyTemplate.OutputPrefixType.RAW));

        return Collections.unmodifiableMap(result);
      }
    };
  }

  private static boolean canUseAesGcmSive() {
    try {
      Cipher.getInstance("AES/GCM-SIV/NoPadding");
      return true;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
      return false;
    }
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (canUseAesGcmSive()) {
      Registry.registerKeyManager(new AesGcmSivKeyManager(), newKeyAllowed);
    }
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM-SIV with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   * </ul>
   *
   * @deprecated use {@code KeyTemplates.get("AES128_GCM_SIV")}
   */
  @Deprecated
  public static final KeyTemplate aes128GcmSivTemplate() {
    return createKeyTemplate(16, KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   * </ul>
   *
   * <p>Keys generated from this template should create ciphertexts compatible with other libraries.
   *
   * @deprecated use {@code KeyTemplates.get("AES128_GCM_SIV_RAW")}
   */
  @Deprecated
  public static final KeyTemplate rawAes128GcmSivTemplate() {
    return createKeyTemplate(16, KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM-SIV with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   * </ul>
   *
   * @deprecated use {@code KeyTemplates.get("AES256_GCM_SIV")}
   */
  @Deprecated
  public static final KeyTemplate aes256GcmSivTemplate() {
    return createKeyTemplate(32, KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM-SIV with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   * </ul>
   *
   * <p>Keys generated from this template should create ciphertexts compatible with other libraries.
   *
   * @deprecated use {@code KeyTemplates.get("AES256_GCM_SIV_RAW")}
   */
  @Deprecated
  public static final KeyTemplate rawAes256GcmSivTemplate() {
    return createKeyTemplate(32, KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * Returns a {@link KeyTemplate} containing a {@link AesGcmSivKeyFormat} with some specified
   * parameters.
   */
  private static KeyTemplate createKeyTemplate(
      int keySize, KeyTemplate.OutputPrefixType prefixType) {
    AesGcmSivKeyFormat format = AesGcmSivKeyFormat.newBuilder().setKeySize(keySize).build();
    return KeyTemplate.create(
        new AesGcmSivKeyManager().getKeyType(), format.toByteArray(), prefixType);
  }

  private static KeyFactory.KeyFormat<AesGcmSivKeyFormat> createKeyFormat(
      int keySize, KeyTemplate.OutputPrefixType prefixType) {
    AesGcmSivKeyFormat format = AesGcmSivKeyFormat.newBuilder().setKeySize(keySize).build();
    return new KeyFactory.KeyFormat<>(format, prefixType);
  }
}
