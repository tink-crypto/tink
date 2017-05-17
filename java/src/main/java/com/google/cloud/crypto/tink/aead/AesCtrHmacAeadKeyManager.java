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

package com.google.cloud.crypto.tink.aead;

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKey;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKeyFormat;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKey;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.mac.HmacKeyManager;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

public final class AesCtrHmacAeadKeyManager
    implements KeyManager<Aead, AesCtrHmacAeadKey, AesCtrHmacAeadKeyFormat> {
  AesCtrHmacAeadKeyManager() {}

  private static final Logger logger =
      Logger.getLogger(AesCtrHmacAeadKeyManager.class.getName());

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey";

  static {
    try {
      // TODO(thaidn): this could be IndCpaCipherFactory.registerStandardKeyTypes();
      Registry.INSTANCE.registerKeyManager(AesCtrKeyManager.TYPE_URL, new AesCtrKeyManager());
      MacFactory.registerStandardKeyTypes();
    } catch (GeneralSecurityException e) {
      logger.severe("cannot register key managers: " + e);
    }
  }

  @Override
  public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      AesCtrHmacAeadKey keyProto = AesCtrHmacAeadKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesCtrHmacAead key");
    }
  }

  @Override
  public Aead getPrimitive(AesCtrHmacAeadKey keyProto) throws GeneralSecurityException {
    validate(keyProto);
    return new EncryptThenAuthenticate(
        Registry.INSTANCE.getPrimitive(AesCtrKeyManager.TYPE_URL, keyProto.getAesCtrKey()),
        Registry.INSTANCE.getPrimitive(HmacKeyManager.TYPE_URL, keyProto.getHmacKey()),
        keyProto.getHmacKey().getParams().getTagSize());
  }

  @Override
  public AesCtrHmacAeadKey newKey(ByteString serialized) throws GeneralSecurityException {
    try {
      AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.parseFrom(serialized);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesCtrHmacAead key format", e);
    }
  }

  @Override
  public AesCtrHmacAeadKey newKey(AesCtrHmacAeadKeyFormat format) throws GeneralSecurityException {
    AesCtrKey aesCtrKey = Registry.INSTANCE.newKey(
        AesCtrKeyManager.TYPE_URL, format.getAesCtrKeyFormat());
    HmacKey hmacKey = Registry.INSTANCE.newKey(HmacKeyManager.TYPE_URL, format.getHmacKeyFormat());
    return AesCtrHmacAeadKey.newBuilder()
        .setAesCtrKey(aesCtrKey)
        .setHmacKey(hmacKey)
        .setVersion(VERSION)
        .build();
  }

  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    AesCtrHmacAeadKey key = newKey(serialized);
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

  private void validate(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
