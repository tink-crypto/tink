// Copyright 2023 Google LLC
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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Test helper key manager emulating a user that has a custom old KeyManager implementation with
 * a custom Mac primitive. In order to test our code handling such cases.
 */
class LegacyHmacTestKeyManager implements KeyManager<Mac> {
  /** Type url that this manager does support. */
  public static final String TYPE_URL = "type.googleapis.com/custom.HmacKey";
  /** Current version of this key manager. Keys with version equal or smaller are supported. */
  private static final int VERSION = 0;

  /** Minimum key size in bytes. */
  private static final int MIN_KEY_SIZE_IN_BYTES = 16;

  /** Minimum tag size in bytes. This provides minimum 80-bit security strength. */
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;

  /** @param serializedKey serialized {@code HmacKey} proto */
  @Override
  public Mac getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      HmacKey keyProto = HmacKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized HmacKey proto", e);
    }
  }

  /** @param key {@code HmacKey} proto */
  @Override
  public Mac getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof HmacKey)) {
      throw new GeneralSecurityException("expected HmacKey proto");
    }
    HmacKey keyProto = (HmacKey) key;
    validate(keyProto);
    HashType hash = keyProto.getParams().getHash();
    byte[] keyValue = keyProto.getKeyValue().toByteArray();
    SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
    int tagSize = keyProto.getParams().getTagSize();
    switch (hash) {
      case SHA1:
        return new LegacyMacTestImpl(new PrfHmacJce("HMACSHA1", keySpec), tagSize);
      case SHA224:
        return new LegacyMacTestImpl(new PrfHmacJce("HMACSHA224", keySpec), tagSize);
      case SHA256:
        return new LegacyMacTestImpl(new PrfHmacJce("HMACSHA256", keySpec), tagSize);
      case SHA384:
        return new LegacyMacTestImpl(new PrfHmacJce("HMACSHA384", keySpec), tagSize);
      case SHA512:
        return new LegacyMacTestImpl(new PrfHmacJce("HMACSHA512", keySpec), tagSize);
      default:
        throw new GeneralSecurityException("unknown hash");
    }
  }

  /**
   * @param serializedKeyFormat serialized {@code HmacKeyFormat} proto
   * @return new {@code HmacKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      HmacKeyFormat format =
          HmacKeyFormat.parseFrom(serializedKeyFormat, ExtensionRegistryLite.getEmptyRegistry());
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized HmacKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code HmacKeyFormat} proto
   * @return new {@code HmacKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof HmacKeyFormat)) {
      throw new GeneralSecurityException("expected HmacKeyFormat proto");
    }
    HmacKeyFormat format = (HmacKeyFormat) keyFormat;
    validate(format);
    return HmacKey.newBuilder()
        .setVersion(VERSION)
        .setParams(format.getParams())
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code HmacKeyFormat} proto
   * @return {@code KeyData} with a new {@code HmacKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    HmacKey key = (HmacKey) newKey(serializedKeyFormat);
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
        .build();
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(TYPE_URL);
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  public Class<Mac> getPrimitiveClass() {
    return Mac.class;
  }

  private void validate(HmacKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() < MIN_KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("key too short");
    }
    validate(key.getParams());
  }

  private void validate(HmacKeyFormat format) throws GeneralSecurityException {
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
      case SHA224:
        if (params.getTagSize() > 28) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA256:
        if (params.getTagSize() > 32) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA384:
        if (params.getTagSize() > 48) {
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

  static void register() throws GeneralSecurityException {
    Registry.registerKeyManager(new LegacyHmacTestKeyManager(), true);
  }

  private static final class LegacyMacTestImpl implements Mac {

    private final PrfHmacJce prfHmac;
    private final int outputLength;

    LegacyMacTestImpl(PrfHmacJce prfHmac, int outputLength) {
      this.prfHmac = prfHmac;
      this.outputLength = outputLength;
    }

    @Override
    public byte[] computeMac(byte[] data) throws GeneralSecurityException {
      return prfHmac.compute(data, outputLength);
    }

    @Override
    public void verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
      if (!Bytes.equal(computeMac(data), mac)) {
        throw new GeneralSecurityException("invalid MAC");
      }
    }
  }
}
