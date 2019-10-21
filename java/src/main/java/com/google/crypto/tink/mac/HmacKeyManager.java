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

import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.MacJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;

/**
 * This key manager generates new {@code HmacKey} keys and produces new instances of {@code MacJce}.
 */
public class HmacKeyManager extends KeyTypeManager<HmacKey> {
  public HmacKeyManager() {
    super(
        HmacKey.class,
        new PrimitiveFactory<Mac, HmacKey>(Mac.class) {
          @Override
          public Mac getPrimitive(HmacKey key) throws GeneralSecurityException {
            HashType hash = key.getParams().getHash();
            byte[] keyValue = key.getKeyValue().toByteArray();
            SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
            int tagSize = key.getParams().getTagSize();
            switch (hash) {
              case SHA1:
                return new MacJce("HMACSHA1", keySpec, tagSize);
              case SHA256:
                return new MacJce("HMACSHA256", keySpec, tagSize);
              case SHA512:
                return new MacJce("HMACSHA512", keySpec, tagSize);
              default:
                throw new GeneralSecurityException("unknown hash");
            }
          }
        });
  }

  private static final int VERSION = 0;
  
  /** Minimum key size in bytes. */
  private static final int MIN_KEY_SIZE_IN_BYTES = 16;

  /** Minimum tag size in bytes. This provides minimum 80-bit security strength. */
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HmacKey";
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
  public void validateKey(HmacKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() < MIN_KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("key too short");
    }
    validateParams(key.getParams());
  }

  @Override
  public HmacKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return HmacKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  private static void validateParams(HmacParams params) throws GeneralSecurityException {
    if (params.getTagSize() < MIN_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("tag size too small");
    }
    switch (params.getHash()) {
      case SHA1:
        if (params.getTagSize() > 20) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA256:
        if (params.getTagSize() > 32) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA512:
        if (params.getTagSize() > 64) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      default:
        throw new GeneralSecurityException("unknown hash type");
    }
  }

  @Override
  public KeyFactory<HmacKeyFormat, HmacKey> keyFactory() {
    return new KeyFactory<HmacKeyFormat, HmacKey>(HmacKeyFormat.class) {
      @Override
      public void validateKeyFormat(HmacKeyFormat format) throws GeneralSecurityException {
        if (format.getKeySize() < MIN_KEY_SIZE_IN_BYTES) {
          throw new GeneralSecurityException("key too short");
        }
        validateParams(format.getParams());
      }

      @Override
      public HmacKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return HmacKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public HmacKey createKey(HmacKeyFormat format) throws GeneralSecurityException {
        return HmacKey.newBuilder()
            .setVersion(VERSION)
            .setParams(format.getParams())
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .build();
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new HmacKeyManager(), newKeyAllowed);
  }
}
