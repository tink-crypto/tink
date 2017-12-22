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
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager generates new {@code AesGcmKey} keys and produces new instances of {@code
 * AesGcmJce}.
 */
class AesGcmKeyManager implements KeyManager<Aead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesGcmKey";

  /** @param serializedKey serialized {@code AesGcmKey} proto */
  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesGcmKey keyProto = AesGcmKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected AesGcmKey proto");
    }
  }

  /** @param key {@code AesGcmKey} proto */
  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesGcmKey)) {
      throw new GeneralSecurityException("expected AesGcmKey proto");
    }
    AesGcmKey keyProto = (AesGcmKey) key;
    validate(keyProto);
    return new AesGcmJce(keyProto.getKeyValue().toByteArray());
  }

  /**
   * @param serializedKeyFormat serialized {@code AesGcmKeyFormat} proto
   * @return new {@code AesGcmKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesGcmKeyFormat format = AesGcmKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesGcmKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesGcmKeyFormat} proto
   * @return new {@code AesGcmKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesGcmKeyFormat)) {
      throw new GeneralSecurityException("expected AesGcmKeyFormat proto");
    }
    AesGcmKeyFormat format = (AesGcmKeyFormat) keyFormat;
    validate(format);
    return AesGcmKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesGcmKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesGcmKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesGcmKey key = (AesGcmKey) newKey(serializedKeyFormat);
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
   * @param jsonKey JSON formatted {@code AesGcmKey}-proto
   * @return {@code AesGcmKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return AesGcmKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code AesGcmKeyFromat}-proto
   * @return {@code AesGcmKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return AesGcmKeyFormat.newBuilder()
          .setKeySize(json.getInt("keySize"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code AesGcmKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    AesGcmKey key;
    try {
      key = AesGcmKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesGcmKey proto", e);
    }
    validate(key);
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("keyValue", Base64.encode(key.getKeyValue().toByteArray()))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKeyFormat}
   * which must be a {@code AesGcmKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesGcmKeyFormat format;
    try {
      format = AesGcmKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesGcmKeyFormat proto", e);
    }
    validate(format);
    try {
      return new JSONObject()
          .put("keySize", format.getKeySize())
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 2 || !json.has("version") || !json.has("keyValue")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validateKeyFormat(JSONObject json) throws JSONException {
    if (json.length() != 1 || !json.has("keySize")) {
      throw new JSONException("Invalid key format.");
    }
  }

  private void validate(AesGcmKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    Validators.validateAesKeySize(key.getKeyValue().size());
  }

  private void validate(AesGcmKeyFormat format) throws GeneralSecurityException {
    Validators.validateAesKeySize(format.getKeySize());
  }
}
