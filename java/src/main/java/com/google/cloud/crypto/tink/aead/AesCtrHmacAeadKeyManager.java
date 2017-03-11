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
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.Util;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

class AesCtrHmacAeadKeyManager implements KeyManager<Aead> {
  private static final Logger logger =
      Logger.getLogger(AesCtrHmacAeadKeyManager.class.getName());

  private static final int VERSION = 0;

  private static final String AES_CTR_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.AesCtrKey";

  private static final String AES_CTR_KEY_FORMAT =
      "type.googleapis.com/google.cloud.crypto.tink.AesCtrKeyFormat";

  private static final String HMAC_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.HmacKey";

  private static final String HMAC_KEY_FORMAT =
      "type.googleapis.com/google.cloud.crypto.tink.HmacKeyFormat";

  private static final String AES_CTR_HMAC_AEAD_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey";

  static {
    try {
      // TODO(thaidn): this could be IndCpaCipherFactory.registerStandardKeyTypes();
      Registry.INSTANCE.registerKeyManager(AES_CTR_KEY_TYPE, new AesCtrKeyManager());
      MacFactory.registerStandardKeyTypes();
    } catch (GeneralSecurityException e) {
      logger.severe("Cannot register key managers: " + e);
    }
  }

  @Override
  public Aead getPrimitive(Any proto) throws GeneralSecurityException {
    try {
      AesCtrHmacAeadKey key = AesCtrHmacAeadKey.parseFrom(proto.getValue());
      validate(key);
      return new EncryptThenAuthenticate(
          Registry.INSTANCE.getPrimitive(Util.pack(AES_CTR_KEY_TYPE, key.getAesCtrKey())),
          Registry.INSTANCE.getPrimitive(Util.pack(HMAC_KEY_TYPE, key.getHmacKey())),
          key.getHmacKey().getParams().getTagSize());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesCtrHmacAead key");
    }
  }

  @Override
  public Any newKey(KeyFormat keyFormat) throws GeneralSecurityException {
    try {
      AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.parseFrom(
          keyFormat.getFormat().getValue());
      Any aesCtrKey = Registry.INSTANCE.newKey(
          KeyFormat.newBuilder()
              .setFormat(Util.pack(AES_CTR_KEY_FORMAT, format.getAesCtrKeyFormat()))
              .setKeyType(AES_CTR_KEY_TYPE)
              .build());
      Any hmacKey = Registry.INSTANCE.newKey(
          KeyFormat.newBuilder()
              .setFormat(Util.pack(HMAC_KEY_FORMAT, format.getHmacKeyFormat()))
              .setKeyType(HMAC_KEY_TYPE)
              .build());
      return Util.pack(AES_CTR_HMAC_AEAD_KEY_TYPE, AesCtrHmacAeadKey.newBuilder()
          .setAesCtrKey(AesCtrKey.parseFrom(aesCtrKey.getValue()))
          .setHmacKey(HmacKey.parseFrom(hmacKey.getValue()))
          .setVersion(VERSION)
          .build());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("cannot generate AesCtrHmacAead key");
    }
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(AES_CTR_HMAC_AEAD_KEY_TYPE);
  }

  private void validate(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
