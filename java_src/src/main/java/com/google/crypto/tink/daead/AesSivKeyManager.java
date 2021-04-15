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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code AesSivKey} keys and produces new instances of {@code
 * AesSiv}.
 */
public final class AesSivKeyManager extends KeyTypeManager<AesSivKey> {
  AesSivKeyManager() {
    super(
        AesSivKey.class,
        new PrimitiveFactory<DeterministicAead, AesSivKey>(DeterministicAead.class) {
          @Override
          public DeterministicAead getPrimitive(AesSivKey key) throws GeneralSecurityException {
            return new AesSiv(key.getKeyValue().toByteArray());
          }
        });
  }

  private static final int KEY_SIZE_IN_BYTES = 64;

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesSivKey";
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
  public void validateKey(AesSivKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    if (key.getKeyValue().size() != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException(
          "invalid key size: "
              + key.getKeyValue().size()
              + ". Valid keys must have "
              + KEY_SIZE_IN_BYTES
              + " bytes.");
    }
  }

  @Override
  public AesSivKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesSivKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesSivKeyFormat, AesSivKey> keyFactory() {
    return new KeyFactory<AesSivKeyFormat, AesSivKey>(AesSivKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesSivKeyFormat format) throws GeneralSecurityException {
        if (format.getKeySize() != KEY_SIZE_IN_BYTES) {
          throw new InvalidAlgorithmParameterException(
              "invalid key size: "
                  + format.getKeySize()
                  + ". Valid keys must have "
                  + KEY_SIZE_IN_BYTES
                  + " bytes.");
        }
      }

      @Override
      public AesSivKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesSivKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesSivKey createKey(AesSivKeyFormat format) throws GeneralSecurityException {
        return AesSivKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setVersion(getVersion())
            .build();
      }

      @Override
      public AesSivKey deriveKey(AesSivKeyFormat format, InputStream inputStream)
          throws GeneralSecurityException {
        Validators.validateVersion(format.getVersion(), getVersion());

        byte[] pseudorandomness = new byte[KEY_SIZE_IN_BYTES];
        try {
          int read = inputStream.read(pseudorandomness);
          if (read != KEY_SIZE_IN_BYTES) {
            throw new GeneralSecurityException("Not enough pseudorandomness given");
          }
          return AesSivKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(pseudorandomness))
              .setVersion(getVersion())
              .build();
        } catch (IOException e) {
          throw new GeneralSecurityException("Reading pseudorandomness failed", e);
        }
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<AesSivKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<AesSivKeyFormat>> result = new HashMap<>();
        result.put(
            "AES256_SIV",
            new KeyFactory.KeyFormat<>(
                AesSivKeyFormat.newBuilder().setKeySize(KEY_SIZE_IN_BYTES).build(),
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "AES256_SIV_RAW",
            new KeyFactory.KeyFormat<>(
                AesSivKeyFormat.newBuilder().setKeySize(KEY_SIZE_IN_BYTES).build(),
                KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesSivKeyManager(), newKeyAllowed);
  }

  /** @return a {@code KeyTemplate} that generates new instances of AES-SIV-CMAC keys. */
  public static final KeyTemplate aes256SivTemplate() {
    return createKeyTemplate(KEY_SIZE_IN_BYTES, KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return A {@code KeyTemplate} that generates new instances of AES-SIV-CMAC keys. Keys generated
   *     from this template create ciphertexts compatible with other libraries.
   */
  public static final KeyTemplate rawAes256SivTemplate() {
    return createKeyTemplate(KEY_SIZE_IN_BYTES, KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return a {@code KeyTemplate} containing a {@code AesSivKeyFormat} with some specified
   *     parameters.
   */
  private static KeyTemplate createKeyTemplate(
      int keySize, KeyTemplate.OutputPrefixType prefixType) {
    AesSivKeyFormat format = AesSivKeyFormat.newBuilder().setKeySize(keySize).build();
    return KeyTemplate.create(
        new AesSivKeyManager().getKeyType(), format.toByteArray(), prefixType);
  }
}
