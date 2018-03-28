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
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * This key manager generates new {@code AesSivKey} keys and produces new instances of {@code
 * AesSiv}.
 */
class AesSivKeyManager implements KeyManager<DeterministicAead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesSivKey";

  /** @param serializedKey serialized {@code AesSivKey} proto */
  @Override
  public DeterministicAead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesSivKey keyProto = AesSivKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected AesSivKey proto");
    }
  }

  /** @param key {@code AesSivKey} proto */
  @Override
  public DeterministicAead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesSivKey)) {
      throw new GeneralSecurityException("expected AesSivKey proto");
    }
    AesSivKey keyProto = (AesSivKey) key;
    validate(keyProto);
    return new AesSiv(keyProto.getKeyValue().toByteArray());
  }

  /**
   * @param serializedKeyFormat serialized {@code AesSivKeyFormat} proto
   * @return new {@code AesSivKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesSivKeyFormat format = AesSivKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesSivKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesSivKeyFormat} proto
   * @return new {@code AesSivKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesSivKeyFormat)) {
      throw new GeneralSecurityException("expected AesSivKeyFormat proto");
    }
    AesSivKeyFormat format = (AesSivKeyFormat) keyFormat;
    validate(format);
    return AesSivKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesSivKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesSivKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesSivKey key = (AesSivKey) newKey(serializedKeyFormat);
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

  private void validate(AesSivKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() != 64) {
      throw new InvalidKeyException(
          "invalid key size: " + key.getKeyValue().size() + ". Valid keys must have 64 bytes.");
    }
  }

  private void validate(AesSivKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() != 64) {
      throw new InvalidAlgorithmParameterException(
          "invalid key size: " + format.getKeySize() + ". Valid keys must have 64 bytes.");
    }
  }
}
