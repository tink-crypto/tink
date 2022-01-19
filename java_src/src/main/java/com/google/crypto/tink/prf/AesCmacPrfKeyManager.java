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

package com.google.crypto.tink.prf;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.AesCmacPrfKey;
import com.google.crypto.tink.proto.AesCmacPrfKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfAesCmac;
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
 * This key manager generates new {@code AesCmacKeyPrf} keys and produces new instances of {@code
 * AesCmacPrf}.
 */
public final class AesCmacPrfKeyManager extends KeyTypeManager<AesCmacPrfKey> {
  AesCmacPrfKeyManager() {
    super(
        AesCmacPrfKey.class,
        new PrimitiveFactory<Prf, AesCmacPrfKey>(Prf.class) {
          @Override
          public Prf getPrimitive(AesCmacPrfKey key) throws GeneralSecurityException {
            return new PrfAesCmac(key.getKeyValue().toByteArray());
          }
        });
  }

  private static final int VERSION = 0;
  private static final int KEY_SIZE_IN_BYTES = 32;

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";
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
  public void validateKey(AesCmacPrfKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    validateSize(key.getKeyValue().size());
  }

  @Override
  public AesCmacPrfKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesCmacPrfKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  private static void validateSize(int size) throws GeneralSecurityException {
    if (size != KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("AesCmacPrfKey size wrong, must be 32 bytes");
    }
  }

  @Override
  public KeyFactory<AesCmacPrfKeyFormat, AesCmacPrfKey> keyFactory() {
    return new KeyFactory<AesCmacPrfKeyFormat, AesCmacPrfKey>(AesCmacPrfKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesCmacPrfKeyFormat format) throws GeneralSecurityException {
        validateSize(format.getKeySize());
      }

      @Override
      public AesCmacPrfKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesCmacPrfKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesCmacPrfKey createKey(AesCmacPrfKeyFormat format) {
        return AesCmacPrfKey.newBuilder()
            .setVersion(VERSION)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<AesCmacPrfKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<AesCmacPrfKeyFormat>> result = new HashMap<>();
        result.put(
            "AES256_CMAC_PRF",
            new KeyFactory.KeyFormat<>(
                AesCmacPrfKeyFormat.newBuilder().setKeySize(32).build(),
                KeyTemplate.OutputPrefixType.RAW));
        // Identical to AES256_CMAC_PRF, needed for backward compatibility with PrfKeyTemplates.
        // TODO(b/185475349): remove this.
        result.put(
            "AES_CMAC_PRF",
            new KeyFactory.KeyFormat<>(
                AesCmacPrfKeyFormat.newBuilder().setKeySize(32).build(),
                KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesCmacPrfKeyManager(), newKeyAllowed);
  }

  /**
   * Returns a {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW}
   * </ul>
   *
   * .
   *
   * @return A {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW}
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("AES256_CMAC_PRF")}
   */
  @Deprecated
  public static final KeyTemplate aes256CmacTemplate() {
    AesCmacPrfKeyFormat format = AesCmacPrfKeyFormat.newBuilder().setKeySize(32).build();
    return KeyTemplate.create(
        new AesCmacPrfKeyManager().getKeyType(),
        format.toByteArray(),
        KeyTemplate.OutputPrefixType.RAW);
  }
}
