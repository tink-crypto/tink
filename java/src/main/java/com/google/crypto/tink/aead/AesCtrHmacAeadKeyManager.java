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
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.IndCpaCipher;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

/**
 * This key manager generates new {@code AesCtrHmacAeadKey} keys and produces new instances
 * of {@code EncryptThenAuthenticate}.
 */
public final class AesCtrHmacAeadKeyManager implements KeyManager<Aead> {
  AesCtrHmacAeadKeyManager() {}

  private static final Logger logger =
      Logger.getLogger(AesCtrHmacAeadKeyManager.class.getName());

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

  static {
    try {
      // TODO(thaidn): this could be IndCpaCipherFactory.registerStandardKeyTypes();
      Registry.INSTANCE.registerKeyManager(AesCtrKeyManager.TYPE_URL, new AesCtrKeyManager());
      MacConfig.registerStandardKeyTypes();
    } catch (GeneralSecurityException e) {
      logger.severe("cannot register key managers: " + e);
    }
  }

  /**
   * @param serializedKey  serialized {@code AesCtrHmacAeadKey} proto
   */
  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesCtrHmacAeadKey keyProto = AesCtrHmacAeadKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrHmacAeadKey proto", e);
    }
  }

  /**
   * @param key  {@code AesCtrHmacAeadKey} proto
   */
  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesCtrHmacAeadKey)) {
      throw new GeneralSecurityException("expected AesCtrHmacAeadKey proto");
    }
    AesCtrHmacAeadKey keyProto = (AesCtrHmacAeadKey) key;
    validate(keyProto);
    return new EncryptThenAuthenticate(
        (IndCpaCipher) Registry.INSTANCE.getPrimitive(
            AesCtrKeyManager.TYPE_URL, keyProto.getAesCtrKey()),
        (Mac) Registry.INSTANCE.getPrimitive(HmacKeyManager.TYPE_URL, keyProto.getHmacKey()),
        keyProto.getHmacKey().getParams().getTagSize());
  }

  /**
   * @param serializedKeyFormat  serialized {@code AesCtrHmacAeadKeyFormat} proto
   * @return new {@code AesCtrHmacAeadKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrHmacAeadKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat  {@code AesCtrHmacAeadKeyFormat} proto
   * @return new {@code AesCtrHmacAeadKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesCtrHmacAeadKeyFormat)) {
      throw new GeneralSecurityException("expected AesCtrHmacAeadKeyFormat proto");
    }
    AesCtrHmacAeadKeyFormat format = (AesCtrHmacAeadKeyFormat) keyFormat;
    AesCtrKey aesCtrKey = (AesCtrKey) Registry.INSTANCE.newKey(
        AesCtrKeyManager.TYPE_URL, format.getAesCtrKeyFormat());
    HmacKey hmacKey = (HmacKey) Registry.INSTANCE.newKey(
        HmacKeyManager.TYPE_URL, format.getHmacKeyFormat());
    return AesCtrHmacAeadKey.newBuilder()
        .setAesCtrKey(aesCtrKey)
        .setHmacKey(hmacKey)
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat  serialized {@code AesCtrHmacAeadKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesCtrHmacAeadKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrHmacAeadKey key = (AesCtrHmacAeadKey) newKey(serializedKeyFormat);
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

  private void validate(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
