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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KmsAeadKey;
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.crypto.tink.subtle.KmsClient;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code GcpKmsAead} or {@code AwsKmsAead}.
 * To use it one must provide a {@code KmsClient}.
 */
public final class KmsAeadKeyManager implements KeyManager<Aead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsAeadKey";

  private final KmsClient kmsClient;

  public KmsAeadKeyManager(KmsClient kmsClient) {
    this.kmsClient = kmsClient;
  }

  /**
   * @param serializedKey  serialized {@code KmsAeadKey} proto
   */
  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      KmsAeadKey keyProto = KmsAeadKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected KmsAeadKey proto", e);
    }
  }

  /**
   * @param key  {@code KmsAeadKey} proto
   */
  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof KmsAeadKey)) {
      throw new GeneralSecurityException("expected KmsAeadKey proto");
    }
    KmsAeadKey keyProto = (KmsAeadKey) key;
    validate(keyProto);
    return kmsClient.getAead(keyProto.getParams().getKeyUri());
  }

  /**
   * @param serializedKeyFormat  serialized {@code KmsAeadKeyFormat} proto
   * @return new {@code KmsAeadKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      KmsAeadKeyFormat format = KmsAeadKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmsAeadKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat  {@code KmsAeadKeyFormat} proto
   * @return new {@code KmsAeadKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat)
      throws GeneralSecurityException {
    if (!(keyFormat instanceof KmsAeadKeyFormat)) {
      throw new GeneralSecurityException("expected KmsAeadKeyFormat proto");
    }
    KmsAeadKeyFormat format = (KmsAeadKeyFormat) keyFormat;
    return KmsAeadKey.newBuilder()
        .setParams(format)
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat  serialized {@code KmsAeadKeyFormat} proto
   * @return {@code KeyData} with a new {@code KmsAeadKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    KmsAeadKey key = (KmsAeadKey) newKey(serializedKeyFormat);
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.REMOTE)
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

  private static void validate(KmsAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
