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

package com.google.crypto.tink.aead.internal;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.AesCtrJceCipher;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Test helper key manager emulating a user that has a custom old KeyManager implementation with a
 * custom StreamingAead primitive. In order to test our code handling such cases.
 */
public class LegacyAesCtrHmacTestKeyManager implements KeyManager<Aead> {

  private static final String TYPE_URL = "type.googleapis.com/custom.AesCtrHmacAeadKey";
  private static final int MIN_AES_CTR_IV_SIZE_IN_BYTES = 12;

  private static void validateHmacParams(HmacParams params) throws GeneralSecurityException {
    if (params.getTagSize() < 10) {
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

  private static void validateHmacKey(HmacKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), /* maxExpected= */ 0);
    if (key.getKeyValue().size() < 16) {
      throw new GeneralSecurityException("key too short");
    }
    validateHmacParams(key.getParams());
  }

  private static Mac getMacPrimitive(HmacKey key) throws GeneralSecurityException {
    HashType hash = key.getParams().getHash();
    byte[] keyValue = key.getKeyValue().toByteArray();
    SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
    int tagSize = key.getParams().getTagSize();
    switch (hash) {
      case SHA1:
        return new PrfMac(new PrfHmacJce("HMACSHA1", keySpec), tagSize);
      case SHA224:
        return new PrfMac(new PrfHmacJce("HMACSHA224", keySpec), tagSize);
      case SHA256:
        return new PrfMac(new PrfHmacJce("HMACSHA256", keySpec), tagSize);
      case SHA384:
        return new PrfMac(new PrfHmacJce("HMACSHA384", keySpec), tagSize);
      case SHA512:
        return new PrfMac(new PrfHmacJce("HMACSHA512", keySpec), tagSize);
      default:
        throw new GeneralSecurityException("unknown hash");
    }
  }

  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    AesCtrHmacAeadKey keyProto;
    try {
      keyProto =
          AesCtrHmacAeadKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("failed to parse the key", e);
    }
    validateKey(keyProto);
    return new EncryptThenAuthenticate(
        new AesCtrJceCipher(
            keyProto.getAesCtrKey().getKeyValue().toByteArray(),
            keyProto.getAesCtrKey().getParams().getIvSize()),
        getMacPrimitive(keyProto.getHmacKey()),
        keyProto.getHmacKey().getParams().getTagSize());
  }

  private void validateKey(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    // Validate overall.
    Validators.validateVersion(key.getVersion(), /* maxExpected= */ 0);

    // Validate AesCtrKey.
    AesCtrKey aesCtrKey = key.getAesCtrKey();
    Validators.validateVersion(aesCtrKey.getVersion(), /* maxExpected= */ 0);
    Validators.validateAesKeySize(aesCtrKey.getKeyValue().size());
    AesCtrParams aesCtrParams = aesCtrKey.getParams();
    if (aesCtrParams.getIvSize() < MIN_AES_CTR_IV_SIZE_IN_BYTES || aesCtrParams.getIvSize() > 16) {
      throw new GeneralSecurityException("invalid AES STR IV size");
    }

    // Validate HmacKey.
    validateHmacKey(key.getHmacKey());
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<Aead> getPrimitiveClass() {
    return Aead.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrHmacAeadKeyFormat format;
    try {
      format =
          AesCtrHmacAeadKeyFormat.parseFrom(
              serializedKeyFormat, ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("failed to parse the key format", e);
    }
    AesCtrKey aesCtrKey =
        AesCtrKey.newBuilder()
            .setParams(format.getAesCtrKeyFormat().getParams())
            .setKeyValue(
                ByteString.copyFrom(Random.randBytes(format.getAesCtrKeyFormat().getKeySize())))
            .setVersion(0)
            .build();
    HmacKey hmacKey =
        HmacKey.newBuilder()
            .setVersion(0)
            .setParams(format.getHmacKeyFormat().getParams())
            .setKeyValue(
                ByteString.copyFrom(Random.randBytes(format.getHmacKeyFormat().getKeySize())))
            .build();
    AesCtrHmacAeadKey key =
        AesCtrHmacAeadKey.newBuilder()
            .setAesCtrKey(aesCtrKey)
            .setHmacKey(hmacKey)
            .setVersion(0)
            .build();
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
        .build();
  }

  public static final KeyTemplate templateWithTinkPrefix() {
    return createKeyTemplate(OutputPrefixType.TINK);
  }

  public static final KeyTemplate templateWithoutPrefix() {
    return createKeyTemplate(OutputPrefixType.RAW);
  }

  private static KeyTemplate createKeyTemplate(OutputPrefixType outputPrefixType) {
    AesCtrHmacAeadKeyFormat format = createKeyFormat(32, 16, 32, 32, HashType.SHA256);
    return KeyTemplate.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(format.toByteString())
        .setOutputPrefixType(outputPrefixType)
        .build();
  }

  private static AesCtrHmacAeadKeyFormat createKeyFormat(
      int aesKeySize, int ivSize, int hmacKeySize, int tagSize, HashType hashType) {
    AesCtrKeyFormat aesCtrKeyFormat =
        AesCtrKeyFormat.newBuilder()
            .setParams(AesCtrParams.newBuilder().setIvSize(ivSize).build())
            .setKeySize(aesKeySize)
            .build();
    HmacKeyFormat hmacKeyFormat =
        HmacKeyFormat.newBuilder()
            .setParams(HmacParams.newBuilder().setHash(hashType).setTagSize(tagSize).build())
            .setKeySize(hmacKeySize)
            .build();
    return AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(aesCtrKeyFormat)
        .setHmacKeyFormat(hmacKeyFormat)
        .build();
  }

  public static void register() throws GeneralSecurityException {
    Registry.registerKeyManager(new LegacyAesCtrHmacTestKeyManager(), true);
  }
}
