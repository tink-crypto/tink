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

import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.MacJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;

/**
 * This key manager generates new {@code HmacKey} keys and produces new instances of {@code MacJce}.
 */
class HmacKeyManager extends KeyManagerBase<Mac, HmacKey, HmacKeyFormat> {
  public HmacKeyManager() {
    super(Mac.class, HmacKey.class, HmacKeyFormat.class, TYPE_URL);
  }
  /** Type url that this manager does support. */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey";
  /** Current version of this key manager. Keys with version equal or smaller are supported. */
  private static final int VERSION = 0;

  /** Minimum key size in bytes. */
  private static final int MIN_KEY_SIZE_IN_BYTES = 16;

  /** Minimum tag size in bytes. This provides minimum 80-bit security strength. */
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;

  /** @param serializedKey serialized {@code HmacKey} proto */
  @Override
  public Mac getPrimitiveFromKey(HmacKey keyProto) throws GeneralSecurityException {
    HashType hash = keyProto.getParams().getHash();
    byte[] keyValue = keyProto.getKeyValue().toByteArray();
    SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
    int tagSize = keyProto.getParams().getTagSize();
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

  /**
   * @param serializedKeyFormat serialized {@code HmacKeyFormat} proto
   * @return new {@code HmacKey} proto
   */
  @Override
  public HmacKey newKeyFromFormat(HmacKeyFormat format) throws GeneralSecurityException {
    return HmacKey.newBuilder()
        .setVersion(VERSION)
        .setParams(format.getParams())
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .build();
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  protected HmacKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return HmacKey.parseFrom(byteString);
  }

  @Override
  protected HmacKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return HmacKeyFormat.parseFrom(byteString);
  }

  @Override
  protected void validateKey(HmacKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() < MIN_KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("key too short");
    }
    validate(key.getParams());
  }

  @Override
  protected void validateKeyFormat(HmacKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() < MIN_KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("key too short");
    }
    validate(format.getParams());
  }

  private void validate(HmacParams params) throws GeneralSecurityException {
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
}
