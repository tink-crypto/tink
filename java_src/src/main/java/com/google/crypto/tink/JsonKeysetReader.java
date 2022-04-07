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

import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.file.Path;

/**
 * A {@link KeysetReader} that can read from source source cleartext or encrypted keysets in <a
 * href="https://developers.google.com/protocol-buffers/docs/reference/java/com/google/protobuf/util/JsonFormat">proto
 * JSON format</a>.
 *
 * @since 1.0.0
 */
public final class JsonKeysetReader implements KeysetReader {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  private final InputStream inputStream;
  private final JsonObject json;
  private boolean urlSafeBase64 = false;

  private JsonKeysetReader(InputStream inputStream) {
    this.inputStream = inputStream;
    json = null;
  }

  /**
   * Static method to create a JsonKeysetReader from an {@link InputStream}.
   *
   * <p>Note: the input stream won't be read until {@link JsonKeysetReader#read} or {@link
   * JsonKeysetReader#readEncrypted} is called.
   */
  public static KeysetReader withInputStream(InputStream input) throws IOException {
    return new JsonKeysetReader(input);
  }

  /**
   * Static method to create a JsonKeysetReader from an {@link JsonObject}.
   *
   * @deprecated Use {@code #withString}
   */
  @Deprecated
  public static JsonKeysetReader withJsonObject(Object input) {
    return withString(input.toString());
  }

  /** Static method to create a JsonKeysetReader from a string. */
  public static JsonKeysetReader withString(String input) {
    return new JsonKeysetReader(new ByteArrayInputStream(input.getBytes(UTF_8)));
  }

  /** Static method to create a JsonKeysetReader from a byte array. */
  public static JsonKeysetReader withBytes(final byte[] bytes) {
    return new JsonKeysetReader(new ByteArrayInputStream(bytes));
  }

  /**
   * Static method to create a JsonKeysetReader from a file.
   *
   * <p>Note: the file won't be read until {@link JsonKeysetReader#read} or {@link
   * JsonKeysetReader#readEncrypted} is called.
   */
  public static JsonKeysetReader withFile(File file) throws IOException {
    return new JsonKeysetReader(new FileInputStream(file));
  }

  /**
   * Static method to create a JsonKeysetReader from a {@link Path}.
   *
   * <p>Note: the file path won't be read until {@link JsonKeysetReader#read} or {@link
   * JsonKeysetReader#readEncrypted} is called.
   *
   * <p>This method only works on Android API level 26 or newer.
   */
  public static JsonKeysetReader withPath(String path) throws IOException {
    return withFile(new File(path));
  }

  /**
   * Static method to create a JsonKeysetReader from a {@link Path}.
   *
   * <p>Note: the file path won't be read until {@link JsonKeysetReader#read} or {@link
   * JsonKeysetReader#readEncrypted} is called.
   *
   * <p>This method only works on Android API level 26 or newer.
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
        JsonReader jsonReader = new JsonReader(
            new StringReader(new String(Util.readAll(inputStream), UTF_8)));
        jsonReader.setLenient(false);
        return keysetFromJson(Streams.parse(jsonReader).getAsJsonObject());
      }
    } catch (JsonParseException | IllegalStateException e) {
      throw new IOException(e);
    } finally {
      if (inputStream != null) {
        inputStream.close();
      }
    }
  }

  @Override
  public EncryptedKeyset readEncrypted() throws IOException {
    try {
      if (json != null) {
        return encryptedKeysetFromJson(json);
      } else {
        return encryptedKeysetFromJson(
            JsonParser.parseString(new String(Util.readAll(inputStream), UTF_8)).getAsJsonObject());
      }
    } catch (JsonParseException | IllegalStateException e) {
      throw new IOException(e);
    } finally {
      if (inputStream != null) {
        inputStream.close();
      }
    }
  }

  private Keyset keysetFromJson(JsonObject json) {
    validateKeyset(json);
    Keyset.Builder builder = Keyset.newBuilder();
    if (json.has("primaryKeyId")) {
      builder.setPrimaryKeyId(json.get("primaryKeyId").getAsInt());
    }
    JsonArray keys = json.getAsJsonArray("key");
    for (int i = 0; i < keys.size(); i++) {
      builder.addKey(keyFromJson(keys.get(i).getAsJsonObject()));
    }
    return builder.build();
  }

  private EncryptedKeyset encryptedKeysetFromJson(JsonObject json) {
    validateEncryptedKeyset(json);
    byte[] encryptedKeyset;
    if (urlSafeBase64) {
      encryptedKeyset = Base64.urlSafeDecode(json.get("encryptedKeyset").getAsString());
    } else {
      encryptedKeyset = Base64.decode(json.get("encryptedKeyset").getAsString());
    }
    return EncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
        .setKeysetInfo(keysetInfoFromJson(json.getAsJsonObject("keysetInfo")))
        .build();
  }

  private Keyset.Key keyFromJson(JsonObject json) {
    validateKey(json);
    return Keyset.Key.newBuilder()
        .setStatus(getStatus(json.get("status").getAsString()))
        .setKeyId(json.get("keyId").getAsInt())
        .setOutputPrefixType(getOutputPrefixType(json.get("outputPrefixType").getAsString()))
        .setKeyData(keyDataFromJson(json.getAsJsonObject("keyData")))
        .build();
  }

  private static KeysetInfo keysetInfoFromJson(JsonObject json) {
    KeysetInfo.Builder builder = KeysetInfo.newBuilder();
    if (json.has("primaryKeyId")) {
      builder.setPrimaryKeyId(json.get("primaryKeyId").getAsInt());
    }
    if (json.has("keyInfo")) {
      JsonArray keyInfos = json.getAsJsonArray("keyInfo");
      for (int i = 0; i < keyInfos.size(); i++) {
        builder.addKeyInfo(keyInfoFromJson(keyInfos.get(i).getAsJsonObject()));
      }
    }
    return builder.build();
  }

  private static KeysetInfo.KeyInfo keyInfoFromJson(JsonObject json) {
    return KeysetInfo.KeyInfo.newBuilder()
        .setStatus(getStatus(json.get("status").getAsString()))
        .setKeyId(json.get("keyId").getAsInt())
        .setOutputPrefixType(getOutputPrefixType(json.get("outputPrefixType").getAsString()))
        .setTypeUrl(json.get("typeUrl").getAsString())
        .build();
  }

  private KeyData keyDataFromJson(JsonObject json) {
    validateKeyData(json);
    byte[] value;
    if (urlSafeBase64) {
      value = Base64.urlSafeDecode(json.get("value").getAsString());
    } else {
      value = Base64.decode(json.get("value").getAsString());
    }
    return KeyData.newBuilder()
        .setTypeUrl(json.get("typeUrl").getAsString())
        .setValue(ByteString.copyFrom(value))
        .setKeyMaterialType(getKeyMaterialType(json.get("keyMaterialType").getAsString()))
        .build();
  }

  private static KeyStatusType getStatus(String status) {
    switch (status) {
      case "ENABLED":
        return KeyStatusType.ENABLED;
      case "DISABLED":
        return KeyStatusType.DISABLED;
      case "DESTROYED":
        return KeyStatusType.DESTROYED;
      default:
        throw new JsonParseException("unknown status: " + status);
    }
  }

  private static OutputPrefixType getOutputPrefixType(String type) {
    switch (type) {
      case "TINK":
        return OutputPrefixType.TINK;
      case "RAW":
        return OutputPrefixType.RAW;
      case "LEGACY":
        return OutputPrefixType.LEGACY;
      case "CRUNCHY":
        return OutputPrefixType.CRUNCHY;
      default:
        throw new JsonParseException("unknown output prefix type: " + type);
    }
  }

  private static KeyMaterialType getKeyMaterialType(String type) {
    switch (type) {
      case "SYMMETRIC":
        return KeyMaterialType.SYMMETRIC;
      case "ASYMMETRIC_PRIVATE":
        return KeyMaterialType.ASYMMETRIC_PRIVATE;
      case "ASYMMETRIC_PUBLIC":
        return KeyMaterialType.ASYMMETRIC_PUBLIC;
      case "REMOTE":
        return KeyMaterialType.REMOTE;
      default:
        throw new JsonParseException("unknown key material type: " + type);
    }
  }

  private static void validateKeyset(JsonObject json) {
    if (!json.has("key") || json.getAsJsonArray("key").size() == 0) {
      throw new JsonParseException("invalid keyset");
    }
  }

  private static void validateEncryptedKeyset(JsonObject json) {
    if (!json.has("encryptedKeyset")) {
      throw new JsonParseException("invalid encrypted keyset");
    }
  }

  private static void validateKey(JsonObject json) {
    if (!json.has("keyData")
        || !json.has("status")
        || !json.has("keyId")
        || !json.has("outputPrefixType")) {
      throw new JsonParseException("invalid key");
    }
  }

  private static void validateKeyData(JsonObject json) {
    if (!json.has("typeUrl") || !json.has("value") || !json.has("keyMaterialType")) {
      throw new JsonParseException("invalid keyData");
    }
  }
}
