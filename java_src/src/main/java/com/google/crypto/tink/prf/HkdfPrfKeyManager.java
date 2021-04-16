// Copyright 2020 Google LLC
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
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code HkdfPrfKey} keys and produces new instances of {@code
 * HkdfStreamingPrf} and {@code HkdfPrf}.
 */
public class HkdfPrfKeyManager extends KeyTypeManager<HkdfPrfKey> {
  private static com.google.crypto.tink.subtle.Enums.HashType convertHash(HashType hashType)
      throws GeneralSecurityException {
    switch (hashType) {
      case SHA1:
        return com.google.crypto.tink.subtle.Enums.HashType.SHA1;
      case SHA256:
        return com.google.crypto.tink.subtle.Enums.HashType.SHA256;
      case SHA384:
        return com.google.crypto.tink.subtle.Enums.HashType.SHA384;
      case SHA512:
        return com.google.crypto.tink.subtle.Enums.HashType.SHA512;
      default:
        throw new GeneralSecurityException("HashType " + hashType.name() + " not known in");
    }
  }

  HkdfPrfKeyManager() {
    super(
        HkdfPrfKey.class,
        new PrimitiveFactory<StreamingPrf, HkdfPrfKey>(StreamingPrf.class) {
          @Override
          public StreamingPrf getPrimitive(HkdfPrfKey key) throws GeneralSecurityException {
            return new HkdfStreamingPrf(
                convertHash(key.getParams().getHash()),
                key.getKeyValue().toByteArray(),
                key.getParams().getSalt().toByteArray());
          }
        },
        new PrimitiveFactory<Prf, HkdfPrfKey>(Prf.class) {
          @Override
          public Prf getPrimitive(HkdfPrfKey key) throws GeneralSecurityException {
            return PrfImpl.wrap(
                new HkdfStreamingPrf(
                    convertHash(key.getParams().getHash()),
                    key.getKeyValue().toByteArray(),
                    key.getParams().getSalt().toByteArray()));
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HkdfPrfKey";
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
  public void validateKey(HkdfPrfKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    validateKeySize(key.getKeyValue().size());
    validateParams(key.getParams());
  }

  @Override
  public HkdfPrfKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return HkdfPrfKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<HkdfPrfKeyFormat, HkdfPrfKey> keyFactory() {
    return new KeyFactory<HkdfPrfKeyFormat, HkdfPrfKey>(HkdfPrfKeyFormat.class) {
      @Override
      public void validateKeyFormat(HkdfPrfKeyFormat format) throws GeneralSecurityException {
        validateKeySize(format.getKeySize());
        validateParams(format.getParams());
      }

      @Override
      public HkdfPrfKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return HkdfPrfKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public HkdfPrfKey createKey(HkdfPrfKeyFormat format) throws GeneralSecurityException {
        return HkdfPrfKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setVersion(getVersion())
            .setParams(format.getParams())
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<HkdfPrfKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<HkdfPrfKeyFormat>> result = new HashMap<>();
        result.put(
            "HKDF_SHA256",
            new KeyFactory.KeyFormat<>(
                HkdfPrfKeyFormat.newBuilder()
                    .setKeySize(32) // the size in bytes of the HKDF key
                    .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
                    .build(),
                KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  // We use a somewhat larger minimum key size than usual, because PRFs might be used by many users,
  // in which case the security can degrade by a factor depending on the number of users. (Discussed
  // for example in https://eprint.iacr.org/2012/159)
  private static final int MIN_KEY_SIZE = 32;

  private static void validateKeySize(int keySize) throws GeneralSecurityException {
    if (keySize < MIN_KEY_SIZE) {
      throw new GeneralSecurityException("Invalid HkdfPrfKey/HkdfPrfKeyFormat: Key size too short");
    }
  }

  private static void validateParams(HkdfPrfParams params) throws GeneralSecurityException {
    // Omitting SHA1 for the moment; there seems to be no reason to allow it.
    if (params.getHash() != HashType.SHA256 && params.getHash() != HashType.SHA512) {
      throw new GeneralSecurityException("Invalid HkdfPrfKey/HkdfPrfKeyFormat: Unsupported hash");
    }
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new HkdfPrfKeyManager(), newKeyAllowed);
  }

  public static String staticKeyType() {
    return new HkdfPrfKeyManager().getKeyType();
  }

  /**
   * Generates a {@link KeyTemplate} for HKDF-PRF keys with the following parameters.
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>HMAC key size: 32 bytes
   *   <li>Salt: empty
   * </ul>
   */
  public static final KeyTemplate hkdfSha256Template() {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32) // the size in bytes of the HKDF key
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    return KeyTemplate.create(
        HkdfPrfKeyManager.staticKeyType(), format.toByteArray(), KeyTemplate.OutputPrefixType.RAW);
  }
}
