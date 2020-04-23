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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * This key manager generates new {@code AesSivKey} keys and produces new instances of {@code
 * AesSiv}.
 */
public class AesSivKeyManager extends KeyTypeManager<AesSivKey> {
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
    if (key.getKeyValue().size() != 64) {
      throw new InvalidKeyException(
          "invalid key size: " + key.getKeyValue().size() + ". Valid keys must have 64 bytes.");
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
        if (format.getKeySize() != 64) {
          throw new InvalidAlgorithmParameterException(
              "invalid key size: " + format.getKeySize() + ". Valid keys must have 64 bytes.");
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
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesSivKeyManager(), newKeyAllowed);
  }
}
