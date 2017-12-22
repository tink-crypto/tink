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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.MacJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * This key manager generates new {@code HmacKey} keys and produces new instances of {@code MacJce}.
 */
class HmacKeyManager implements KeyManager<Mac> {
  /** Type url that this manager does support. */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacKey";
  /** Current version of this key manager. Keys with version equal or smaller are supported. */
  private static final int VERSION = 0;

  /** Minimum key size in bytes. */
  private static final int MIN_KEY_SIZE_IN_BYTES = 16;

  /** Minimum tag size in bytes. This provides minimum 80-bit security strength. */
  private static final int MIN_TAG_SIZE_IN_BYTES = 10;

  /** @param serializedKey serialized {@code HmacKey} proto */
  @Override
  public Mac getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      HmacKey keyProto = HmacKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized HmacKey proto", e);
    }
  }

  /** @param key {@code HmacKey} proto */
  @Override
  public Mac getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof HmacKey)) {
      throw new GeneralSecurityException("expected HmacKey proto");
    }
    HmacKey keyProto = (HmacKey) key;
    validate(keyProto);
    HashType hash = keyProto.getParams().getHash();
    byte[] keyValue = keyProto.getKeyValue().toByteArray();
    SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
    int tagSize = keyProto.getParams().getTagSize();
    switch (hash) {
      case SHA1:
        return new MacJce("HMACSHA1", keySpec, tagSize);
      case SHA256:
        return new MacJce("HMACSHA256", keySpec, tagSize);
      case SHA512:
        return new MacJce("HMACSHA512", keySpec, tagSize);
      default:
        throw new GeneralSecurityException("unknown hash");
    }
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
   * @param serializedKeyFormat serialized {@code HmacKeyFormat} proto
   * @return new {@code HmacKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      HmacKeyFormat format = HmacKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized HmacKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat {@code HmacKeyFormat} proto
   * @return new {@code HmacKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    if (!(keyFormat instanceof HmacKeyFormat)) {
      throw new GeneralSecurityException("expected HmacKeyFormat proto");
    }
    HmacKeyFormat format = (HmacKeyFormat) keyFormat;
    validate(format);
    return HmacKey.newBuilder()
        .setVersion(VERSION)
        .setParams(format.getParams())
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .build();
  }

  /**
   * @param serializedKeyFormat serialized {@code HmacKeyFormat} proto
   * @return {@code KeyData} with a new {@code HmacKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    HmacKey key = (HmacKey) newKey(serializedKeyFormat);
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
        .build();
  }

  /**
   * @param jsonKey JSON formatted {@code HmacKey}-proto
   * @return {@code HmacKey}-proto
   */
  @Override
  public MessageLite jsonToKey(final byte[] jsonKey) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKey, Util.UTF_8));
      validateKey(json);
      byte[] keyValue = Base64.decode(json.getString("keyValue"));
      return HmacKey.newBuilder()
          .setVersion(json.getInt("version"))
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeyValue(ByteString.copyFrom(keyValue))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * @param jsonKeyFormat JSON formatted {@code HmacKeyFromat}-proto
   * @return {@code HmacKeyFormat}-proto
   */
  @Override
  public MessageLite jsonToKeyFormat(final byte[] jsonKeyFormat) throws GeneralSecurityException {
    try {
      JSONObject json = new JSONObject(new String(jsonKeyFormat, Util.UTF_8));
      validateKeyFormat(json);
      return HmacKeyFormat.newBuilder()
          .setParams(paramsFromJson(json.getJSONObject("params")))
          .setKeySize(json.getInt("keySize"))
          .build();
    } catch (JSONException e) {
      throw new GeneralSecurityException(e);
    }
  }

  /**
   * Returns a JSON-formatted serialization of the given {@code serializedKey},
   * which must be a {@code HmacKey}-proto.
   * @throws GeneralSecurityException if the key in {@code serializedKey} is not supported
   */
  @Override
  public byte[] keyToJson(ByteString serializedKey) throws GeneralSecurityException {
    HmacKey key;
    try {
      key = HmacKey.parseFrom(serializedKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized HmacKey proto", e);
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
   * which must be a {@code HmacKeyFormat}-proto.
   * @throws GeneralSecurityException if the format in {@code serializedKeyFromat} is not supported
   */
  @Override
  public byte[] keyFormatToJson(ByteString serializedKeyFormat) throws GeneralSecurityException {
    HmacKeyFormat format;
    try {
      format = HmacKeyFormat.parseFrom(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized HmacKeyFormat proto", e);
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

  private JSONObject toJson(HmacParams params) throws JSONException {
    return new JSONObject()
        .put("hash", params.getHash().toString())
        .put("tagSize", params.getTagSize());
  }

  private HmacParams paramsFromJson(JSONObject json)
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

  private void validate(HmacKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() < MIN_KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("key too short");
    }
    validate(key.getParams());
  }

  private void validate(HmacKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() < MIN_KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("key too short");
    }
    validate(format.getParams());
  }

  private void validate(HmacParams params) throws GeneralSecurityException {
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
