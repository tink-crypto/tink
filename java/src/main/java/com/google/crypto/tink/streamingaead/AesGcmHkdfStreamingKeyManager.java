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
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code AesGcmHkdfStreamingKey} keys and produces new instances of
 * {@code AesGcmHkdfStreaming}.
 */
class AesGcmHkdfStreamingKeyManager implements KeyManager<StreamingAead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  /** @param serializedKey serialized {@code AesGcmHkdfStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesGcmHkdfStreamingKey keyProto = AesGcmHkdfStreamingKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected AesGcmHkdfStreamingKey proto");
    }
  }

  /** @param key {@code AesGcmHkdfStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesGcmHkdfStreamingKey)) {
      throw new GeneralSecurityException("expected AesGcmHkdfStreamingKey proto");
    }
    AesGcmHkdfStreamingKey keyProto = (AesGcmHkdfStreamingKey) key;
    validate(keyProto);
    return new AesGcmHkdfStreaming(
        keyProto.getKeyValue().toByteArray(),
        keyProto.getParams().getDerivedKeySize(),
        keyProto.getParams().getCiphertextSegmentSize(),
        /* firstSegmentOffset= */ 0);
  }

  /**
   * @param serializedKeyFormat serialized {@code AesGcmHkdfStreamingKeyFormat} proto
   * @return new {@code AesGcmHkdfStreamingKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesGcmHkdfStreamingKeyFormat format =
          AesGcmHkdfStreamingKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "expected serialized AesGcmHkdfStreamingKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesGcmHkdfStreamingKeyFormat} proto
   * @return new {@code AesGcmHkdfStreamingKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesGcmHkdfStreamingKeyFormat)) {
      throw new GeneralSecurityException("expected AesGcmHkdfStreamingKeyFormat proto");
    }
    AesGcmHkdfStreamingKeyFormat format = (AesGcmHkdfStreamingKeyFormat) keyFormat;
    validate(format);
    return AesGcmHkdfStreamingKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesGcmHkdfStreamingKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesGcmHkdfStreamingKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesGcmHkdfStreamingKey key = (AesGcmHkdfStreamingKey) newKey(serializedKeyFormat);
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

  private void validate(AesGcmHkdfStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    validate(key.getParams());
  }

  private void validate(AesGcmHkdfStreamingKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() < 16) {
      throw new GeneralSecurityException("key_size must be at least 16 bytes");
    }
    validate(format.getParams());
  }

  private void validate(AesGcmHkdfStreamingParams params) throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() != HashType.SHA256) {
      throw new GeneralSecurityException("Only hkdf_hash_type equal to SHA256 is supported");
    }
    if (params.getCiphertextSegmentSize() < params.getDerivedKeySize() + 8) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + 8)");
    }
  }
}
