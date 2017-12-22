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
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager generates new {@code KmsEnvelopeAeadKey} keys and produces new instances of
 * {@code KmsEnvelopeAead}.
 */
class KmsEnvelopeAeadKeyManager implements KeyManager<Aead> {

  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

  /** @param serializedKey serialized {@code KmsEnvelopeAeadKey} proto */
  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKey keyProto = KmsEnvelopeAeadKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmSEnvelopeAeadKey proto", e);
    }
  }

  /** @param key {@code KmsEnvelopeAeadKey} proto */
  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof KmsEnvelopeAeadKey)) {
      throw new GeneralSecurityException("expected KmsEnvelopeAeadKey proto");
    }
    KmsEnvelopeAeadKey keyProto = (KmsEnvelopeAeadKey) key;
    validate(keyProto);
    String keyUri = keyProto.getParams().getKekUri();
    KmsClient kmsClient = KmsClients.get(keyUri);
    Aead remote = kmsClient.getAead(keyUri);
    return new KmsEnvelopeAead(keyProto.getParams().getDekTemplate(), remote);
  }

  /**
   * @param serializedKeyFormat serialized {@code KmsEnvelopeAeadKeyFormat} proto
   * @return new {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmsEnvelopeAeadKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code KmsEnvelopeAeadKeyFormat} proto
   * @return new {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof KmsEnvelopeAeadKeyFormat)) {
      throw new GeneralSecurityException("expected KmsEnvelopeAeadKeyFormat proto");
    }
    KmsEnvelopeAeadKeyFormat format = (KmsEnvelopeAeadKeyFormat) keyFormat;
    return KmsEnvelopeAeadKey.newBuilder().setParams(format).setVersion(VERSION).build();
  }

  /**
   * @param serializedKeyFormat serialized {@code KmsEnvelopeAeadKeyFormat} proto
   * @return {@code KeyData} with a new {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    KmsEnvelopeAeadKey key = (KmsEnvelopeAeadKey) newKey(serializedKeyFormat);
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
   * @param jsonKey JSON formatted {@code KmsEnvelopeAeadKey}-proto
   * @return {@code KmsEnvelopeAeadKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      return KmsEnvelopeAeadKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code KmsEnvelopeAeadKeyFromat}-proto
   * @return {@code KmsEnvelopeAeadKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return keyFormatFromJson(json);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code KmsEnvelopeAeadKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    KmsEnvelopeAeadKey key;
    try {
      key = KmsEnvelopeAeadKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmsEnvelopeAeadKey proto", e);
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
   * which must be a {@code KmsEnvelopeAeadKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    KmsEnvelopeAeadKeyFormat format;
    try {
      format = KmsEnvelopeAeadKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmsEnvelopeAeadKeyFormat proto", e);
    }
    validate(format);
    try {
      return toJson(format).toString(4).getBytes(Util.UTF_8);
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  private JSONObject toJson(KmsEnvelopeAeadKeyFormat format)
      throws JSONException, GeneralSecurityException {
    return new JSONObject()
        .put("kekUri", format.getKekUri())
        .put("dekTemplate", Util.toJson(format.getDekTemplate()));
  }

  private KmsEnvelopeAeadKeyFormat keyFormatFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 2 || !json.has("kekUri") || !json.has("dekTemplate")) {
      throw new JSONException("Invalid params.");
    }
    return KmsEnvelopeAeadKeyFormat.newBuilder()
        .setKekUri(json.getString("kekUri"))
        .setDekTemplate(Util.keyTemplateFromJson(json.getJSONObject("dekTemplate")))
        .build();
  }

  private KmsEnvelopeAeadKeyFormat paramsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    return keyFormatFromJson(json);
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (json.length() != 2 || !json.has("version") || !json.has("params")) {
      throw new JSONException("Invalid key.");
    }
  }

  private void validateKeyFormat(JSONObject json) throws JSONException {
    if (json.length() != 2 || !json.has("kekUri") || !json.has("dekTemplate")) {
      throw new JSONException("Invalid key format.");
    }
  }

  private void validate(KmsEnvelopeAeadKeyFormat format) throws GeneralSecurityException {
  }

  private void validate(KmsEnvelopeAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
  }
}
