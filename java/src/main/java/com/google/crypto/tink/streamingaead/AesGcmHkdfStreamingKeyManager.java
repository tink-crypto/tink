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
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
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
 * This key manager generates new {@code AesGcmHkdfStreamingKey} keys and produces new instances of
 * {@code AesGcmHkdfStreaming}.
 */
class AesGcmHkdfStreamingKeyManager implements KeyManager<StreamingAead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

  /** @param serializedKey serialized {@code AesGcmHkdfStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesGcmHkdfStreamingKey keyProto = AesGcmHkdfStreamingKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected AesGcmHkdfStreamingKey proto");
    }
  }

  /** @param key {@code AesGcmHkdfStreamingKey} proto */
  @Override
  public StreamingAead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof AesGcmHkdfStreamingKey)) {
      throw new GeneralSecurityException("expected AesGcmHkdfStreamingKey proto");
    }
    AesGcmHkdfStreamingKey keyProto = (AesGcmHkdfStreamingKey) key;
    validate(keyProto);
    return new AesGcmHkdfStreaming(
        keyProto.getKeyValue().toByteArray(),
        StreamingAeadUtil.toHmacAlgo(
            keyProto.getParams().getHkdfHashType()),
        keyProto.getParams().getDerivedKeySize(),
        keyProto.getParams().getCiphertextSegmentSize(),
        /* firstSegmentOffset= */ 0);
  }

  /**
   * @param serializedKeyFormat serialized {@code AesGcmHkdfStreamingKeyFormat} proto
   * @return new {@code AesGcmHkdfStreamingKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      AesGcmHkdfStreamingKeyFormat format =
          AesGcmHkdfStreamingKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "expected serialized AesGcmHkdfStreamingKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code AesGcmHkdfStreamingKeyFormat} proto
   * @return new {@code AesGcmHkdfStreamingKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof AesGcmHkdfStreamingKeyFormat)) {
      throw new GeneralSecurityException("expected AesGcmHkdfStreamingKeyFormat proto");
    }
    AesGcmHkdfStreamingKeyFormat format = (AesGcmHkdfStreamingKeyFormat) keyFormat;
    validate(format);
    return AesGcmHkdfStreamingKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code AesGcmHkdfStreamingKeyFormat} proto
   * @return {@code KeyData} proto with a new {@code AesGcmHkdfStreamingKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesGcmHkdfStreamingKey key = (AesGcmHkdfStreamingKey) newKey(serializedKeyFormat);
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
   * @param jsonKey JSON formatted {@code AesGcmHkdfStreamingKey}-proto
   * @return {@code AesGcmHkdfStreamingKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return AesGcmHkdfStreamingKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code AesGcmHkdfStreamingKeyFromat}-proto
   * @return {@code AesGcmHkdfStreamingKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return AesGcmHkdfStreamingKeyFormat.newBuilder()
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeySize(json.getInt("keySize"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code AesGcmHkdfStreamingKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    AesGcmHkdfStreamingKey key;
    try {
      key = AesGcmHkdfStreamingKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized AesGcmHkdfStreamingKey proto", e);
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
   * which must be a {@code AesGcmHkdfStreamingKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    AesGcmHkdfStreamingKeyFormat format;
    try {
      format = AesGcmHkdfStreamingKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "expected serialized AesGcmHkdfStreamingKeyFormat proto", e);
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

  private JSONObject toJson(AesGcmHkdfStreamingParams params) throws JSONException {
    return new JSONObject()
        .put("ciphertextSegmentSize", params.getCiphertextSegmentSize())
        .put("derivedKeySize", params.getDerivedKeySize())
        .put("hkdfHashType", params.getHkdfHashType().toString());
  }

  private AesGcmHkdfStreamingParams paramsFromJson(JSONObject json)
      throws JSONException, GeneralSecurityException {
    if (json.length() != 3 || !json.has("ciphertextSegmentSize") || !json.has("derivedKeySize")
        || !json.has("hkdfHashType")) {
      throw new JSONException("Invalid params.");
    }
    return AesGcmHkdfStreamingParams.newBuilder()
        .setCiphertextSegmentSize(json.getInt("ciphertextSegmentSize"))
        .setDerivedKeySize(json.getInt("derivedKeySize"))
        .setHkdfHashType(Util.getHashType(json.getString("hkdfHashType")))
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

  private void validate(AesGcmHkdfStreamingKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    validate(key.getParams());
  }

  private void validate(AesGcmHkdfStreamingKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() < 16) {
      throw new GeneralSecurityException("key_size must be at least 16 bytes");
    }
    validate(format.getParams());
  }

  private void validate(AesGcmHkdfStreamingParams params) throws GeneralSecurityException {
    Validators.validateAesKeySize(params.getDerivedKeySize());
    if (params.getHkdfHashType() == HashType.UNKNOWN_HASH) {
      throw new GeneralSecurityException("unknown HKDF hash type");
    }
    if (params.getCiphertextSegmentSize() < params.getDerivedKeySize() + 8) {
      throw new GeneralSecurityException(
          "ciphertext_segment_size must be at least (derived_key_size + 8)");
    }
  }
}
