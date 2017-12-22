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
// //////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKey;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesCtrHmacStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesCtrHmacStreaming;
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
 * This key manager generates new {@code AesCtrHmacStreamingKey} keys and produces new instances of
 * {@code AesCtrHmacStreaming}.
 */
class AesCtrHmacStreamingKeyManager implements KeyManager<StreamingAead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

  /** Minimum tag size in bytes. This provides minimum 80-bit security strength. */
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;

  /** @param serializedKey serialized {@code AesCtrHmacStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesCtrHmacStreamingKey keyProto = AesCtrHmacStreamingKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected AesCtrHmacStreamingKey proto", e);
    }
  }

  /** @param key {@code AesCtrHmacStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesCtrHmacStreamingKey)) {
      throw new GeneralSecurityException("expected AesCtrHmacStreamingKey proto");
    }
    AesCtrHmacStreamingKey keyProto = (AesCtrHmacStreamingKey) key;
    validate(keyProto);
    return new AesCtrHmacStreaming(
        keyProto.getKeyValue().toByteArray(),
        StreamingAeadUtil.toHmacAlgo(
            keyProto.getParams().getHkdfHashType()),
        keyProto.getParams().getDerivedKeySize(),
        StreamingAeadUtil.toHmacAlgo(
            keyProto.getParams().getHmacParams().getHash()),
        keyProto.getParams().getHmacParams().getTagSize(),
        keyProto.getParams().getCiphertextSegmentSize(),
        /* firstSegmentOffset= */ 0);
  }

  /**
   * @param serializedKeyFormat serialized {@code AesCtrHmacStreamingKeyFormat} proto
   * @return new {@code AesCtrHmacStreamingKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesCtrHmacStreamingKeyFormat format =
          AesCtrHmacStreamingKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "expected serialized AesCtrHmacStreamingKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesCtrHmacStreamingKeyFormat} proto
   * @return new {@code AesCtrHmacStreamingKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesCtrHmacStreamingKeyFormat)) {
      throw new GeneralSecurityException("expected AesCtrHmacStreamingKeyFormat proto");
    }
    AesCtrHmacStreamingKeyFormat format = (AesCtrHmacStreamingKeyFormat) keyFormat;
    validate(format);
    return AesCtrHmacStreamingKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesCtrHmacStreamingKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesCtrHmacStreamingKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrHmacStreamingKey key = (AesCtrHmacStreamingKey) newKey(serializedKeyFormat);
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
   * @param jsonKey JSON formatted {@code AesCtrHmacStreamingKey}-proto
   * @return {@code AesCtrHmacStreamingKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return AesCtrHmacStreamingKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code AesCtrHmacStreamingKeyFromat}-proto
   * @return {@code AesCtrHmacStreamingKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return AesCtrHmacStreamingKeyFormat.newBuilder()
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeySize(json.getInt("keySize"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code AesCtrHmacStreamingKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    AesCtrHmacStreamingKey key;
    try {
      key = AesCtrHmacStreamingKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesCtrHmacStreamingKey proto", e);
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
   * which must be a {@code AesCtrHmacStreamingKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesCtrHmacStreamingKeyFormat format;
    try {
      format = AesCtrHmacStreamingKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "expected serialized AesCtrHmacStreamingKeyFormat proto", e);
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

  private JSONObject toJson(AesCtrHmacStreamingParams params) throws JSONException {
    return new JSONObject()
        .put("ciphertextSegmentSize", params.getCiphertextSegmentSize())
        .put("derivedKeySize", params.getDerivedKeySize())
        .put("hkdfHashType", params.getHkdfHashType().toString())
        .put("hmacParams", toJson(params.getHmacParams()));
  }

  private JSONObject toJson(HmacParams params) throws JSONException {
    return new JSONObject()
        .put("hash", params.getHash().toString())
        .put("tagSize", params.getTagSize());
  }

  private AesCtrHmacStreamingParams paramsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 4 || !json.has("ciphertextSegmentSize") || !json.has("derivedKeySize")
        || !json.has("hkdfHashType") || !json.has("hmacParams")) {
      throw new JSONException("Invalid params.");
    }
    return AesCtrHmacStreamingParams.newBuilder()
        .setCiphertextSegmentSize(json.getInt("ciphertextSegmentSize"))
        .setDerivedKeySize(json.getInt("derivedKeySize"))
        .setHkdfHashType(Util.getHashType(json.getString("hkdfHashType")))
        .setHmacParams(hmacParamsFromJson(json.getJSONObject("hmacParams")))
        .build();
  }

  private HmacParams hmacParamsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 2 || !json.has("hash") || !json.has("tagSize")) {
      throw new JSONException("Invalid params.");
    }
    return HmacParams.newBuilder()
        .setHash(Util.getHashType(json.getString("hash")))
        .setTagSize(json.getInt("tagSize"))
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

  private void validate(AesCtrHmacStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() < 16) {
      throw new GeneralSecurityException("key_value must have at least 16 bytes");
    }
    if (key.getKeyValue().size() < key.getParams().getDerivedKeySize()) {
      throw new GeneralSecurityException(
          "key_value must have at least as many bits as derived keys");
    }
    validate(key.getParams());
  }

  private void validate(AesCtrHmacStreamingKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() < 16) {
      throw new GeneralSecurityException("key_size must be at least 16 bytes");
    }
    validate(format.getParams());
  }

  private void validate(AesCtrHmacStreamingParams params) throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HKDF hash type");
    }
    if (params.getHmacParams().getHash() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HMAC hash type");
    }
    validateHmacParams(params.getHmacParams());

    if (params.getCiphertextSegmentSize()
        < params.getDerivedKeySize() + params.getHmacParams().getTagSize() + 8) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + tag_size + 8)");
    }
  }

  private void validateHmacParams(HmacParams params) throws GeneralSecurityException {
    if (params.getTagSize() < MIN_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("tag size too small");
    }
    switch (params.getHash()) {
      case SHA1:
        if (params.getTagSize() > 20) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA256:
        if (params.getTagSize() > 32) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      case SHA512:
        if (params.getTagSize() > 64) {
          throw new GeneralSecurityException("tag size too big");
        }
        break;
      default:
        throw new GeneralSecurityException("unknown hash type");
    }
  }
}
