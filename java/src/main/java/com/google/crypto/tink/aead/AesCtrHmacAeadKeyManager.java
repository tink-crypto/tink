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
import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.IndCpaCipher;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@link AesCtrHmacAeadKey} keys and produces new instances of
 * {@link EncryptThenAuthenticate}.
 */
class AesCtrHmacAeadKeyManager
    extends KeyManagerBase<Aead, AesCtrHmacAeadKey, AesCtrHmacAeadKeyFormat> {
  public AesCtrHmacAeadKeyManager() throws GeneralSecurityException {
    super(Aead.class, AesCtrHmacAeadKey.class, AesCtrHmacAeadKeyFormat.class, TYPE_URL);
    Registry.registerKeyManager(new AesCtrKeyManager());
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

  @Override
  public Aead getPrimitiveFromKey(AesCtrHmacAeadKey keyProto) throws GeneralSecurityException {
    return new EncryptThenAuthenticate(
        Registry.getPrimitive(
            AesCtrKeyManager.TYPE_URL, keyProto.getAesCtrKey(), IndCpaCipher.class),
        Registry.getPrimitive(MacConfig.HMAC_TYPE_URL, keyProto.getHmacKey(), Mac.class),
        keyProto.getHmacKey().getParams().getTagSize());
  }

  @Override
  public AesCtrHmacAeadKey newKeyFromFormat(AesCtrHmacAeadKeyFormat format)
      throws GeneralSecurityException {
    AesCtrKey aesCtrKey =
        (AesCtrKey) Registry.newKey(AesCtrKeyManager.TYPE_URL, format.getAesCtrKeyFormat());
    HmacKey hmacKey = (HmacKey) Registry.newKey(MacConfig.HMAC_TYPE_URL, format.getHmacKeyFormat());
    return AesCtrHmacAeadKey.newBuilder()
        .setAesCtrKey(aesCtrKey)
        .setHmacKey(hmacKey)
        .setVersion(VERSION)
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
  protected AesCtrHmacAeadKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesCtrHmacAeadKey.parseFrom(byteString);
  }

  @Override
  protected AesCtrHmacAeadKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesCtrHmacAeadKeyFormat.parseFrom(byteString);
  }

  @Override
  protected void validateKeyFormat(AesCtrHmacAeadKeyFormat format) throws GeneralSecurityException {
    Validators.validateAesKeySize(format.getAesCtrKeyFormat().getKeySize());
  }

  @Override
  protected void validateKey(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
  }
}
