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
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KmsAeadKey;
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager produces new instances of {@code Aead} that forwards encrypt/decrypt
 * requests to a key residing in a remote KMS.
 */
class KmsAeadKeyManager implements KeyManager<Aead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsAeadKey";

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
    String keyUri = keyProto.getParams().getKeyUri();
    KmsClient kmsClient = KmsClients.get(keyUri);
    return kmsClient.getAead(keyUri);
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

  /**
   * @param jsonKey JSON formatted {@code KmsAeadKey}-proto
   * @return {@code KmsAeadKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      return KmsAeadKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code KmsAeadKeyFromat}-proto
   * @return {@code KmsAeadKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return KmsAeadKeyFormat.newBuilder()
          .setKeyUri(json.getString("keyUri"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code KmsAeadKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    KmsAeadKey key;
    try {
      key = KmsAeadKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmsAeadKey proto", e);
    }
    validate(key);
    try {
      return new JSONObject()
          .put("version", key.getVersion())
          .put("params", toJson(key.getParams()))
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKeyFormat}
   * which must be a {@code KmsAeadKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    KmsAeadKeyFormat format;
    try {
      format = KmsAeadKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmsAeadKeyFormat proto", e);
    }
    validate(format);
    try {
      return new JSONObject()
          .put("keyUri", format.getKeyUri())
          .toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  private JSONObject toJson(KmsAeadKeyFormat format) throws JSONException {
    return new JSONObject()
        .put("keyUri", format.getKeyUri());
  }

  private KmsAeadKeyFormat paramsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 1 || !json.has("keyUri")) {
      throw new JSONException("Invalid params.");
    }
    return KmsAeadKeyFormat.newBuilder()
        .setKeyUri(json.getString("keyUri"))
        .build();
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 2 || !json.has("version") || !json.has("params")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validateKeyFormat(JSONObject json) throws JSONException {
    if (json.length() != 1 || !json.has("keyUri")) {
      throw new JSONException("Invalid key format.");
    }
  }

  private static void validate(KmsAeadKeyFormat format) throws GeneralSecurityException {
    if (format.getKeyUri().isEmpty()) {
      throw new GeneralSecurityException("key_uri field must be non-empty");
    }
  }

  private static void validate(KmsAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
  }
}
