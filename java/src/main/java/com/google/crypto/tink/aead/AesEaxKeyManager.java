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
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesEaxJce;
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
 * This key manager generates new {@code AesEaxKey} keys and produces new instances of {@code
 * AesEaxJce}.
 */
class AesEaxKeyManager implements KeyManager<Aead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesEaxKey";

  /** @param serializedKey serialized {@code AesEaxKey} proto */
  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesEaxKey keyProto = AesEaxKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesEaxKey proto", e);
    }
  }

  /** @param key {@code AesEaxKey} proto */
  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesEaxKey)) {
      throw new GeneralSecurityException("expected AesEaxKey proto");
    }
    AesEaxKey keyProto = (AesEaxKey) key;
    validate(keyProto);
    return new AesEaxJce(keyProto.getKeyValue().toByteArray(), keyProto.getParams().getIvSize());
  }

  /**
   * @param serializedKeyFormat serialized {@code AesEaxKeyFormat} proto
   * @return new {@code AesEaxKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesEaxKeyFormat format = AesEaxKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesEaxKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesEaxKeyFormat} proto
   * @return new {@code AesEaxKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesEaxKeyFormat)) {
      throw new GeneralSecurityException("expected AesEaxKeyFormat proto");
    }
    AesEaxKeyFormat format = (AesEaxKeyFormat) keyFormat;
    validate(format);
    return AesEaxKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesEaxKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesEaxKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesEaxKey key = (AesEaxKey) newKey(serializedKeyFormat);
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
   * @param jsonKey JSON formatted {@code AesEaxKey}-proto
   * @return {@code AesEaxKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return AesEaxKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code AesEaxKeyFromat}-proto
   * @return {@code AesEaxKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return AesEaxKeyFormat.newBuilder()
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeySize(json.getInt("keySize"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code AesEaxKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    AesEaxKey key;
    try {
      key = AesEaxKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesEaxKey proto", e);
    }
    validate(key);
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("params", toJson(key.getParams()))
          .put("keyValue", Base64.encode(key.getKeyValue().toByteArray()))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKeyFormat}
   * which must be a {@code AesEaxKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesEaxKeyFormat format;
    try {
      format = AesEaxKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesEaxKeyFormat proto", e);
    }
    validate(format);
    try {
      return new JSONObject()
          .put("params", toJson(format.getParams()))
          .put("keySize", format.getKeySize())
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  private JSONObject toJson(AesEaxParams params) throws JSONException {
    return new JSONObject()
        .put("ivSize", params.getIvSize());
  }

  private AesEaxParams paramsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 1 || !json.has("ivSize")) {
      throw new JSONException("Invalid params.");
    }
    return AesEaxParams.newBuilder()
        .setIvSize(json.getInt("ivSize"))
        .build();
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 3 || !json.has("version") || !json.has("params")
        || !json.has("keyValue")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validateKeyFormat(JSONObject json) throws JSONException {
    if (json.length() != 2 || !json.has("params") || !json.has("keySize")) {
      throw new JSONException("Invalid key format.");
    }
  }

  private void validate(AesEaxKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    Validators.validateAesKeySize(key.getKeyValue().size());
    if (key.getParams().getIvSize() != 12 && key.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }

  private void validate(AesEaxKeyFormat format) throws GeneralSecurityException {
    Validators.validateAesKeySize(format.getKeySize());
    if (format.getParams().getIvSize() != 12 && format.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }
}
