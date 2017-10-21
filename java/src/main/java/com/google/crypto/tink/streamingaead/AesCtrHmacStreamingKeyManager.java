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
// //////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKey;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesCtrHmacStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code AesCtrHmacStreamingKey} keys and produces new instances of
 * {@code AesCtrHmacStreaming}.
 */
class AesCtrHmacStreamingKeyManager implements KeyManager<StreamingAead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

  /** Minimum tag size in bytes. This provides minimum 80-bit security strength. */
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;

  /** @param serializedKey serialized {@code AesCtrHmacStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesCtrHmacStreamingKey keyProto = AesCtrHmacStreamingKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected AesCtrHmacStreamingKey proto", e);
    }
  }

  /** @param key {@code AesCtrHmacStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesCtrHmacStreamingKey)) {
      throw new GeneralSecurityException("expected AesCtrHmacStreamingKey proto");
    }
    AesCtrHmacStreamingKey keyProto = (AesCtrHmacStreamingKey) key;
    validate(keyProto);
    return new AesCtrHmacStreaming(
        keyProto.getKeyValue().toByteArray(),
        StreamingAeadUtil.toHmacAlgo(
            keyProto.getParams().getHkdfHashType()),
        keyProto.getParams().getDerivedKeySize(),
        StreamingAeadUtil.toHmacAlgo(
            keyProto.getParams().getHmacParams().getHash()),
        keyProto.getParams().getHmacParams().getTagSize(),
        keyProto.getParams().getCiphertextSegmentSize(),
        /* firstSegmentOffset= */ 0);
  }

  /**
   * @param serializedKeyFormat serialized {@code AesCtrHmacStreamingKeyFormat} proto
   * @return new {@code AesCtrHmacStreamingKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesCtrHmacStreamingKeyFormat format =
          AesCtrHmacStreamingKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "expected serialized AesCtrHmacStreamingKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesCtrHmacStreamingKeyFormat} proto
   * @return new {@code AesCtrHmacStreamingKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesCtrHmacStreamingKeyFormat)) {
      throw new GeneralSecurityException("expected AesCtrHmacStreamingKeyFormat proto");
    }
    AesCtrHmacStreamingKeyFormat format = (AesCtrHmacStreamingKeyFormat) keyFormat;
    validate(format);
    return AesCtrHmacStreamingKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesCtrHmacStreamingKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesCtrHmacStreamingKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrHmacStreamingKey key = (AesCtrHmacStreamingKey) newKey(serializedKeyFormat);
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

  private void validate(AesCtrHmacStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() < 16) {
      throw new GeneralSecurityException("key_value must have at least 16 bytes");
    }
    if (key.getKeyValue().size() < key.getParams().getDerivedKeySize()) {
      throw new GeneralSecurityException(
          "key_value must have at least as many bits as derived keys");
    }
    validate(key.getParams());
  }

  private void validate(AesCtrHmacStreamingKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() < 16) {
      throw new GeneralSecurityException("key_size must be at least 16 bytes");
    }
    validate(format.getParams());
  }

  private void validate(AesCtrHmacStreamingParams params) throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HKDF hash type");
    }
    if (params.getHmacParams().getHash() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HMAC hash type");
    }
    validateHmacParams(params.getHmacParams());

    if (params.getCiphertextSegmentSize()
        < params.getDerivedKeySize() + params.getHmacParams().getTagSize() + 8) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + tag_size + 8)");
    }
  }

  private void validateHmacParams(HmacParams params) throws GeneralSecurityException {
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
