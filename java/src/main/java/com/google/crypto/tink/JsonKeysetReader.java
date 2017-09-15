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

package com.google.crypto.tink;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.KeysetInfo.KeyInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A {@link KeysetReader} that can read from source source cleartext or encrypted keysets in proto
 * JSON format.
 */
public final class JsonKeysetReader implements KeysetReader {
  private final InputStream inputStream;
  private final JSONObject json;
  private boolean urlSafeBase64 = false;

  private JsonKeysetReader(InputStream inputStream) {
    this.inputStream = inputStream;
    json = null;
  }

  private JsonKeysetReader(JSONObject json) {
    this.json = json;
    this.inputStream = null;
  }

  /**
   * Note: the input stream won't be read until {@link JsonKeysetReader#read} or
   * {@link JsonKeysetReader#readEncrypted} is called.
   */
  public static KeysetReader withInputStream(InputStream input) throws IOException {
    return new JsonKeysetReader(input);
  }

  public static JsonKeysetReader withJsonObject(JSONObject input) {
    return new JsonKeysetReader(input);
  }

  public static JsonKeysetReader withString(String input) {
    return new JsonKeysetReader(new ByteArrayInputStream(input.getBytes(UTF_8)));
  }

  public static JsonKeysetReader withBytes(final byte[] bytes) {
    return new JsonKeysetReader(new ByteArrayInputStream(bytes));
  }

  /**
   * Note: the file won't be read until {@link JsonKeysetReader#read} or
   * {@link JsonKeysetReader#readEncrypted} is called.
   */
  public static JsonKeysetReader withFile(File file) throws IOException {
    return new JsonKeysetReader(new FileInputStream(file));
  }

  /**
   * Note: the file path won't be read until {@link JsonKeysetReader#read} or
   * {@link JsonKeysetReader#readEncrypted} is called.
   */
  public static JsonKeysetReader withPath(String path) throws IOException {
    return withFile(new File(path));
  }

  /**
   * Note: the file path won't be read until {@link JsonKeysetReader#read} or
   * {@link JsonKeysetReader#readEncrypted} is called.
   */
  public static JsonKeysetReader withPath(Path path) throws IOException {
    return withFile(path.toFile());
  }

  public JsonKeysetReader withUrlSafeBase64() {
    this.urlSafeBase64 = true;
    return this;
  }

  @Override
  public Keyset read() throws IOException {
    try {
      if (json != null) {
        return keysetFromJson(json);
      } else {
        return keysetFromJson(new JSONObject(
            new String(Util.readAll(inputStream), UTF_8)));
      }
    } catch (JSONException e) {
      throw new IOException(e);
    }
  }

  @Override
  public EncryptedKeyset readEncrypted() throws IOException {
    try {
      if (json != null) {
        return encryptedKeysetFromJson(json);
      } else {
        return encryptedKeysetFromJson(new JSONObject(
            new String(Util.readAll(inputStream), UTF_8)));
      }
    } catch (JSONException e) {
      throw new IOException(e);
    }
  }

  private Keyset keysetFromJson(JSONObject json) throws JSONException {
    validateKeyset(json);
    Keyset.Builder builder = Keyset.newBuilder();
    if (json.has("primaryKeyId")) {
      builder.setPrimaryKeyId(json.getInt("primaryKeyId"));
    }
    JSONArray keys = json.getJSONArray("key");
    for (int i = 0; i < keys.length(); i++) {
      builder.addKey(keyFromJson(keys.getJSONObject(i)));
    }
    return builder.build();
  }

  private EncryptedKeyset encryptedKeysetFromJson(JSONObject json) throws JSONException {
    validateEncryptedKeyset(json);
    byte[] encryptedKeyset;
    if (urlSafeBase64) {
      encryptedKeyset = Base64.urlSafeDecode(json.getString("encryptedKeyset"));
    } else {
      encryptedKeyset = Base64.decode(json.getString("encryptedKeyset"));
    }
    return EncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
        .setKeysetInfo(keysetInfoFromJson(json.getJSONObject("keysetInfo")))
        .build();
  }

  private Key keyFromJson(JSONObject json) throws JSONException {
    validateKey(json);
    return Key.newBuilder()
        .setStatus(getStatus(json.getString("status")))
        .setKeyId(json.getInt("keyId"))
        .setOutputPrefixType(getOutputPrefixType(json.getString("outputPrefixType")))
        .setKeyData(keyDataFromJson(json.getJSONObject("keyData")))
        .build();
  }

  private KeysetInfo keysetInfoFromJson(JSONObject json) throws JSONException {
    KeysetInfo.Builder builder = KeysetInfo.newBuilder();
    if (json.has("primaryKeyId")) {
      builder.setPrimaryKeyId(json.getInt("primaryKeyId"));
    }
    if (json.has("keyInfo")) {
      JSONArray keyInfos = json.getJSONArray("keyInfo");
      for (int i = 0; i < keyInfos.length(); i++) {
        builder.addKeyInfo(keyInfoFromJson(keyInfos.getJSONObject(i)));
      }
    }
    return builder.build();
  }

  private KeyInfo keyInfoFromJson(JSONObject json) throws JSONException {
    return KeyInfo.newBuilder()
        .setStatus(getStatus(json.getString("status")))
        .setKeyId(json.getInt("keyId"))
        .setOutputPrefixType(getOutputPrefixType(json.getString("outputPrefixType")))
        .setTypeUrl(json.getString("typeUrl"))
        .build();
  }

  private KeyData keyDataFromJson(JSONObject json) throws JSONException {
    validateKeyData(json);
    byte[] value;
    if (urlSafeBase64) {
      value = Base64.urlSafeDecode(json.getString("value"));
    } else {
      value = Base64.decode(json.getString("value"));
    }
    return KeyData.newBuilder()
        .setTypeUrl(json.getString("typeUrl"))
        .setValue(ByteString.copyFrom(value))
        .setKeyMaterialType(getKeyMaterialType(json.getString("keyMaterialType")))
        .build();
  }

  private KeyStatusType getStatus(String status) throws JSONException {
    if (status.equals("ENABLED")) {
      return KeyStatusType.ENABLED;
    } else if (status.equals("DISABLED")) {
      return KeyStatusType.DISABLED;
    }
    throw new JSONException("unknown status: " + status);
  }

  private OutputPrefixType getOutputPrefixType(String type) throws JSONException {
    if (type.equals("TINK")) {
      return OutputPrefixType.TINK;
    } else if (type.equals("RAW")) {
      return OutputPrefixType.RAW;
    } else if (type.equals("LEGACY")) {
      return OutputPrefixType.LEGACY;
    } else if (type.equals("CRUNCHY")) {
      return OutputPrefixType.CRUNCHY;
    }
    throw new JSONException("unknown output prefix type: " + type);
  }

  private KeyMaterialType getKeyMaterialType(String type) throws JSONException {
    if (type.equals("SYMMETRIC")) {
      return KeyMaterialType.SYMMETRIC;
    } else if (type.equals("ASYMMETRIC_PRIVATE")) {
      return KeyMaterialType.ASYMMETRIC_PRIVATE;
    } else if (type.equals("ASYMMETRIC_PUBLIC")) {
      return KeyMaterialType.ASYMMETRIC_PUBLIC;
    } else if (type.equals("REMOTE")) {
      return KeyMaterialType.REMOTE;
    }
    throw new JSONException("unknown key material type: " + type);
  }

  private void validateKeyset(JSONObject json) throws JSONException {
    if (!json.has("key") || json.getJSONArray("key").length() == 0) {
      throw new JSONException("invalid keyset");
    }
  }

  private void validateEncryptedKeyset(JSONObject json) throws JSONException {
    if (!json.has("encryptedKeyset")) {
      throw new JSONException("invalid encrypted keyset");
    }
  }

  private void validateKey(JSONObject json) throws JSONException {
    if (!json.has("keyData")
        || !json.has("status")
        || !json.has("keyId")
        || !json.has("outputPrefixType")) {
      throw new JSONException("invalid key");
    }
  }

  private void validateKeyData(JSONObject json) throws JSONException {
    if (!json.has("typeUrl") || !json.has("value") || !json.has("keyMaterialType")) {
      throw new JSONException("invalid keyData");
    }
  }
}
