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
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code AesGcmKey} keys and produces new instances of {@code
 * AesGcmJce}.
 */
public final class AesGcmKeyManager extends KeyTypeManager<AesGcmKey> {
  AesGcmKeyManager() {
    super(
        AesGcmKey.class,
        new PrimitiveFactory<Aead, AesGcmKey>(Aead.class) {
          @Override
          public Aead getPrimitive(AesGcmKey key) throws GeneralSecurityException {
            return new AesGcmJce(key.getKeyValue().toByteArray());
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesGcmKey";
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
  public void validateKey(AesGcmKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    Validators.validateAesKeySize(key.getKeyValue().size());
  }

  @Override
  public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesGcmKeyFormat, AesGcmKey> keyFactory() {
    return new KeyFactory<AesGcmKeyFormat, AesGcmKey>(AesGcmKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesGcmKeyFormat format) throws GeneralSecurityException {
        Validators.validateAesKeySize(format.getKeySize());
      }

      @Override
      public AesGcmKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesGcmKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesGcmKey createKey(AesGcmKeyFormat format) throws GeneralSecurityException {
        return AesGcmKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setVersion(getVersion())
            .build();
      }

      @Override
      public AesGcmKey deriveKey(AesGcmKeyFormat format, InputStream inputStream)
          throws GeneralSecurityException {
        Validators.validateVersion(format.getVersion(), getVersion());

        byte[] pseudorandomness = new byte[format.getKeySize()];
        try {
          int read = inputStream.read(pseudorandomness);
          if (read != format.getKeySize()) {
            throw new GeneralSecurityException("Not enough pseudorandomness given");
          }
          return AesGcmKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(pseudorandomness))
              .setVersion(getVersion())
              .build();
        } catch (IOException e) {
          throw new GeneralSecurityException("Reading pseudorandomness failed", e);
        }
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<AesGcmKeyFormat>> keyFormats() {
        Map<String, KeyFactory.KeyFormat<AesGcmKeyFormat>> result = new HashMap<>();
        result.put("AES128_GCM", createKeyFormat(16, KeyTemplate.OutputPrefixType.TINK));
        result.put("AES128_GCM_RAW", createKeyFormat(16, KeyTemplate.OutputPrefixType.RAW));
        result.put("AES256_GCM", createKeyFormat(32, KeyTemplate.OutputPrefixType.TINK));
        result.put("AES256_GCM_RAW", createKeyFormat(32, KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesGcmKeyManager(), newKeyAllowed);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate aes128GcmTemplate() {
    return createKeyTemplate(16, KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   *     <p>Keys generated from this template should create ciphertexts compatible with other
   *     libraries.
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate rawAes128GcmTemplate() {
    return createKeyTemplate(16, KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate aes256GcmTemplate() {
    return createKeyTemplate(32, KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   *     <p>Keys generated from this template should create ciphertexts compatible with other
   *     libraries.
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate rawAes256GcmTemplate() {
    return createKeyTemplate(32, KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link AesGcmKeyFormat} with some specified
   *     parameters.
   */
  private static KeyTemplate createKeyTemplate(
      int keySize, KeyTemplate.OutputPrefixType prefixType) {
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(keySize).build();
    return KeyTemplate.create(
        new AesGcmKeyManager().getKeyType(), format.toByteArray(), prefixType);
  }

  private static KeyFactory.KeyFormat<AesGcmKeyFormat> createKeyFormat(
      int keySize, KeyTemplate.OutputPrefixType prefixType) {
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(keySize).build();
    return new KeyFactory.KeyFormat<>(format, prefixType);
  }
}
