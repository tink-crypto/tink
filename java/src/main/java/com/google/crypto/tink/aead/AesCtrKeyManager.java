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

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesCtrJceCipher;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.IndCpaCipher;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager generates new {@code AesCtrKey} keys and produces new instances of {@code
 * AesCtrJceCipher}.
 */
class AesCtrKeyManager implements KeyManager<IndCpaCipher> {
  private static final int VERSION = 0;

  static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesCtrKey";

  // In counter mode each message is encrypted with an initialization vector (IV) that must be
  // unique. If one single IV is ever used to encrypt two or more messages, the confidentiality of
  // these messages might be lost. This cipher uses a randomly generated IV for each message. The
  // birthday paradox says that if one encrypts 2^k messages, the probability that the random IV
  // will repeat is roughly 2^{2k - t}, where t is the size in bits of the IV. Thus with 96-bit
  // (12-byte) IV, if one encrypts 2^32 messages the probability of IV collision is less than
  // 2^-33 (i.e., less than one in eight billion).
  private static final int MIN_IV_SIZE_IN_BYTES = 12;

  /** @param serializedKey serialized {@code AesCtrKey} proto */
  @Override
  public AesCtrJceCipher getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesCtrKey keyProto = AesCtrKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrKey proto", e);
    }
  }

  /** @param key {@code AesCtrKey} proto */
  @Override
  public AesCtrJceCipher getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesCtrKey)) {
      throw new GeneralSecurityException("expected AesCtrKey proto");
    }
    AesCtrKey keyProto = (AesCtrKey) key;
    validate(keyProto);
    return new AesCtrJceCipher(
        keyProto.getKeyValue().toByteArray(), keyProto.getParams().getIvSize());
  }

  /**
   * @param serializedKeyFormat serialized {@code AesCtrKeyFormat} proto
   * @return new {@code AesCtrKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesCtrKeyFormat format = AesCtrKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesCtrKeyFormat} proto
   * @return new {@code AesCtrKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesCtrKeyFormat)) {
      throw new GeneralSecurityException("expected AesCtrKeyFormat proto");
    }
    AesCtrKeyFormat format = (AesCtrKeyFormat) keyFormat;
    validate(format);
    return AesCtrKey.newBuilder()
        .setParams(format.getParams())
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesCtrKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesCtrKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrKey key = (AesCtrKey) newKey(serializedKeyFormat);
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
   * @param jsonKey JSON formatted {@code AesCtrKey}-proto
   * @return {@code AesCtrKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return AesCtrKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code AesCtrKeyFromat}-proto
   * @return {@code AesCtrKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return AesCtrKeyFormat.newBuilder()
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeySize(json.getInt("keySize"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code AesCtrKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    AesCtrKey key;
    try {
      key = AesCtrKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrKey proto", e);
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
   * which must be a {@code AesCtrKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrKeyFormat format;
    try {
      format = AesCtrKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrKeyFormat proto", e);
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

  private JSONObject toJson(AesCtrParams params) throws JSONException {
    return new JSONObject()
        .put("ivSize", params.getIvSize());
  }

  private AesCtrParams paramsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 1 || !json.has("ivSize")) {
      throw new JSONException("Invalid params.");
    }
    return AesCtrParams.newBuilder()
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

  private void validate(AesCtrKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    Validators.validateAesKeySize(key.getKeyValue().size());
    validate(key.getParams());
  }

  private void validate(AesCtrKeyFormat format) throws GeneralSecurityException {
    Validators.validateAesKeySize(format.getKeySize());
    validate(format.getParams());
  }

  private void validate(AesCtrParams params) throws GeneralSecurityException {
    if (params.getIvSize() < MIN_IV_SIZE_IN_BYTES || params.getIvSize() > 16) {
      throw new GeneralSecurityException("invalid IV size");
    }
  }
}
