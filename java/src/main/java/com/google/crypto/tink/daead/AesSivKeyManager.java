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
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import org.json.JSONException;
import org.json.JSONObject;

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

  /**
   * @param jsonKey JSON formatted {@code AesSivKey}-proto
   * @return {@code AesSivKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return AesSivKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code AesSivKeyFromat}-proto
   * @return {@code AesSivKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return AesSivKeyFormat.newBuilder()
          .setKeySize(json.getInt("keySize"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code AesSivKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    AesSivKey key;
    try {
      key = AesSivKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesSivKey proto", e);
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
   * which must be a {@code AesSivKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesSivKeyFormat format;
    try {
      format = AesSivKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesSivKeyFormat proto", e);
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

  private void validate(AesSivKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() != 48 && key.getKeyValue().size() != 64) {
      throw new InvalidKeyException("invalid key size: " + key.getKeyValue().size()
          + ". Acceptable values are 48 and 64 bytes.");
    }
  }

  private void validate(AesSivKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() != 48 && format.getKeySize() != 64) {
      throw new InvalidAlgorithmParameterException("invalid key size: " + format.getKeySize()
          + ". Acceptable values are 48 and 64 bytes.");
    }
  }
}
