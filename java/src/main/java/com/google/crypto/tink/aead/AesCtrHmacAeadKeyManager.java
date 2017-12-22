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
import com.google.crypto.tink.Util;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.IndCpaCipher;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager generates new {@link AesCtrHmacAeadKey} keys and produces new instances
 * of {@link EncryptThenAuthenticate}.
 */
class AesCtrHmacAeadKeyManager implements KeyManager<Aead> {
  AesCtrHmacAeadKeyManager() throws GeneralSecurityException {
    Registry.registerKeyManager(AesCtrKeyManager.TYPE_URL, new AesCtrKeyManager());
  }

  private static final Logger logger =
      Logger.getLogger(AesCtrHmacAeadKeyManager.class.getName());

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

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
        (IndCpaCipher) Registry.getPrimitive(
            AesCtrKeyManager.TYPE_URL, keyProto.getAesCtrKey()),
        (Mac) Registry.getPrimitive(MacConfig.HMAC_TYPE_URL, keyProto.getHmacKey()),
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
    AesCtrKey aesCtrKey = (AesCtrKey) Registry.newKey(
        AesCtrKeyManager.TYPE_URL, format.getAesCtrKeyFormat());
    HmacKey hmacKey = (HmacKey) Registry.newKey(
        MacConfig.HMAC_TYPE_URL, format.getHmacKeyFormat());
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

  @Override
  public int getVersion() {
    return VERSION;
  }

  /**
   * @param jsonKey JSON formatted {@code AesCtrHmacAeadKey}-proto
   * @return {@code AesCtrHmacAeadKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      KeyManager<IndCpaCipher> aesCtrKeyManager = Registry.getKeyManager(AesCtrKeyManager.TYPE_URL);
      KeyManager<Mac> hmacKeyManager = Registry.getKeyManager(MacConfig.HMAC_TYPE_URL);
      return AesCtrHmacAeadKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setAesCtrKey((AesCtrKey) aesCtrKeyManager.jsonToKey(
              json.getJSONObject("aesCtrKey").toString(4).getBytes(Util.UTF_8)))
          .setHmacKey((HmacKey) hmacKeyManager.jsonToKey(
              json.getJSONObject("hmacKey").toString(4).getBytes(Util.UTF_8)))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code AesCtrHmacAeadKeyFromat}-proto
   * @return {@code AesCtrHmacAeadKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      KeyManager<IndCpaCipher> aesCtrKeyManager = Registry.getKeyManager(AesCtrKeyManager.TYPE_URL);
      KeyManager<Mac> hmacKeyManager = Registry.getKeyManager(MacConfig.HMAC_TYPE_URL);
      return AesCtrHmacAeadKeyFormat.newBuilder()
          .setAesCtrKeyFormat((AesCtrKeyFormat) aesCtrKeyManager.jsonToKeyFormat(
              json.getJSONObject("aesCtrKeyFormat").toString(4).getBytes(Util.UTF_8)))
          .setHmacKeyFormat((HmacKeyFormat) hmacKeyManager.jsonToKeyFormat(
              json.getJSONObject("hmacKeyFormat").toString(4).getBytes(Util.UTF_8)))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code AesCtrHmacAeadKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    AesCtrHmacAeadKey key;
    try {
      key = AesCtrHmacAeadKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrHmacAeadKey proto", e);
    }
    validate(key);
    KeyManager<IndCpaCipher> aesCtrKeyManager = Registry.getKeyManager(AesCtrKeyManager.TYPE_URL);
    KeyManager<Mac> hmacKeyManager = Registry.getKeyManager(MacConfig.HMAC_TYPE_URL);
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("aesCtrKey", new JSONObject(new String(
              aesCtrKeyManager.keyToJson(key.getAesCtrKey().toByteString()), Util.UTF_8)))
          .put("hmacKey", new JSONObject(new String(
              hmacKeyManager.keyToJson(key.getHmacKey().toByteString()), Util.UTF_8)))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKeyFormat}
   * which must be a {@code AesCtrHmacAeadKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializeKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrHmacAeadKeyFormat format;
    try {
      format = AesCtrHmacAeadKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrHmacAeadKeyFormat proto", e);
    }
    validate(format);
    KeyManager<IndCpaCipher> aesCtrKeyManager = Registry.getKeyManager(AesCtrKeyManager.TYPE_URL);
    KeyManager<Mac> hmacKeyManager = Registry.getKeyManager(MacConfig.HMAC_TYPE_URL);
    try {
      return new JSONObject()
          .put("aesCtrKeyFormat", new JSONObject(new String(
              aesCtrKeyManager.keyFormatToJson(
                  format.getAesCtrKeyFormat().toByteString()), Util.UTF_8)))
          .put("hmacKeyFormat", new JSONObject(new String(
              hmacKeyManager.keyFormatToJson(
                  format.getHmacKeyFormat().toByteString()), Util.UTF_8)))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 3 || !json.has("version")
        || !json.has("aesCtrKey") || !json.has("hmacKey")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validateKeyFormat(JSONObject json) throws JSONException {
    if (json.length() != 2 || !json.has("aesCtrKeyFormat") || !json.has("hmacKeyFormat")) {
      throw new JSONException("Invalid key format.");
    }
  }

  private void validate(AesCtrHmacAeadKeyFormat format) throws GeneralSecurityException {
    Validators.validateAesKeySize(format.getAesCtrKeyFormat().getKeySize());
  }

  private void validate(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    Validators.validateAesKeySize(key.getAesCtrKey().getKeyValue().size());
  }
}
