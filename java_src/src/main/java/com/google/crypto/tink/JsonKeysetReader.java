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

import androidx.annotation.RequiresApi;
import com.google.crypto.tink.internal.JsonParser;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.InlineMe;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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

  private static final long MAX_KEY_ID = 4294967295L;  // = 2^32 - 1
  private static final long MIN_KEY_ID = Integer.MIN_VALUE;  // = - 2^31

  private final InputStream inputStream;
  private boolean urlSafeBase64 = false;

  private JsonKeysetReader(InputStream inputStream) {
    this.inputStream = inputStream;
  }

  /**
   * Static method to create a JsonKeysetReader from an {@link InputStream}.
   *
   * <p>Note: the input stream won't be read until {@link JsonKeysetReader#read} or {@link
   * JsonKeysetReader#readEncrypted} is called.
   */
  @SuppressWarnings("CheckedExceptionNotThrown")
  public static JsonKeysetReader withInputStream(InputStream input) throws IOException {
    return new JsonKeysetReader(input);
  }

  /**
   * Static method to create a JsonKeysetReader from an {@link JsonObject}.
   *
   * @deprecated Use {@code #withString}
   */
  @InlineMe(
      replacement = "JsonKeysetReader.withString(input.toString())",
      imports = "com.google.crypto.tink.JsonKeysetReader")
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
   *
   * @deprecated Method should be inlined.
   */
  @InlineMe(
      replacement = "JsonKeysetReader.withInputStream(new FileInputStream(file))",
      imports = {"com.google.crypto.tink.JsonKeysetReader", "java.io.FileInputStream"})
  @Deprecated
  public static JsonKeysetReader withFile(File file) throws IOException {
    return withInputStream(new FileInputStream(file));
  }

  /**
   * Static method to create a JsonKeysetReader from a {@link Path}.
   *
   * <p>Note: the file path won't be read until {@link JsonKeysetReader#read} or {@link
   * JsonKeysetReader#readEncrypted} is called.
   *
   * <p>This method only works on Android API level 26 or newer.
   *
   * @deprecated Method should be inlined.
   */
  @InlineMe(
      replacement = "JsonKeysetReader.withInputStream(new FileInputStream(new File(path)))",
      imports = {
        "com.google.crypto.tink.JsonKeysetReader",
        "java.io.File",
        "java.io.FileInputStream"
      })
  @Deprecated
  public static JsonKeysetReader withPath(String path) throws IOException {
    return withInputStream(new FileInputStream(new File(path)));
  }

  /**
   * Static method to create a JsonKeysetReader from a {@link Path}.
   *
   * <p>Note: the file path won't be read until {@link JsonKeysetReader#read} or {@link
   * JsonKeysetReader#readEncrypted} is called.
   *
   * <p>This method only works on Android API level 26 or newer.
   *
   * @deprecated Method should be inlined.
   */
  @InlineMe(
      replacement = "JsonKeysetReader.withInputStream(new FileInputStream(path.toFile()))",
      imports = {"com.google.crypto.tink.JsonKeysetReader", "java.io.FileInputStream"})
  @RequiresApi(26) // https://developer.android.com/reference/java/nio/file/Path
  @Deprecated
  public static JsonKeysetReader withPath(Path path) throws IOException {
    return JsonKeysetReader.withInputStream(new FileInputStream(path.toFile()));
  }

  @CanIgnoreReturnValue
  public JsonKeysetReader withUrlSafeBase64() {
    this.urlSafeBase64 = true;
    return this;
  }

  @Override
  public Keyset read() throws IOException {
    try {
      return keysetFromJson(
          JsonParser.parse(new String(Util.readAll(inputStream), UTF_8)).getAsJsonObject());
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
      return encryptedKeysetFromJson(
          JsonParser.parse(new String(Util.readAll(inputStream), UTF_8)).getAsJsonObject());
    } catch (JsonParseException | IllegalStateException e) {
      throw new IOException(e);
    } finally {
      if (inputStream != null) {
        inputStream.close();
      }
    }
  }

  private static int getKeyId(JsonElement element) throws IOException {
    long id;
    try {
      id = JsonParser.getParsedNumberAsLongOrThrow(element);
    } catch (NumberFormatException e) {
      throw new IOException(e);
    }
    if (id > MAX_KEY_ID || id < MIN_KEY_ID) {
      throw new IOException("invalid key id");
    }
    // casts large unsigned int32 numbers to negative int32 numbers
    return (int) element.getAsLong();
  }

  private Keyset keysetFromJson(JsonObject json) throws IOException {
    validateKeyset(json);
    Keyset.Builder builder = Keyset.newBuilder();
    if (json.has("primaryKeyId")) {
      builder.setPrimaryKeyId(getKeyId(json.get("primaryKeyId")));
    }
    JsonArray keys = json.getAsJsonArray("key");
    for (int i = 0; i < keys.size(); i++) {
      builder.addKey(keyFromJson(keys.get(i).getAsJsonObject()));
    }
    return builder.build();
  }

  private EncryptedKeyset encryptedKeysetFromJson(JsonObject json) throws IOException {
    validateEncryptedKeyset(json);
    byte[] encryptedKeyset;
    if (urlSafeBase64) {
      encryptedKeyset = Base64.urlSafeDecode(json.get("encryptedKeyset").getAsString());
    } else {
      encryptedKeyset = Base64.decode(json.get("encryptedKeyset").getAsString());
    }
    if (json.has("keysetInfo")) {
      return EncryptedKeyset.newBuilder()
          .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
          .setKeysetInfo(keysetInfoFromJson(json.getAsJsonObject("keysetInfo")))
          .build();
    } else {
      return EncryptedKeyset.newBuilder()
          .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
          .build();
    }
  }

  private Keyset.Key keyFromJson(JsonObject json) throws IOException {
    validateKey(json);
    return Keyset.Key.newBuilder()
        .setStatus(getStatus(json.get("status").getAsString()))
        .setKeyId(getKeyId(json.get("keyId")))
        .setOutputPrefixType(getOutputPrefixType(json.get("outputPrefixType").getAsString()))
        .setKeyData(keyDataFromJson(json.getAsJsonObject("keyData")))
        .build();
  }

  private static KeysetInfo keysetInfoFromJson(JsonObject json) throws IOException {
    KeysetInfo.Builder builder = KeysetInfo.newBuilder();
    if (json.has("primaryKeyId")) {
      builder.setPrimaryKeyId(getKeyId(json.get("primaryKeyId")));
    }
    if (json.has("keyInfo")) {
      JsonArray keyInfos = json.getAsJsonArray("keyInfo");
      for (int i = 0; i < keyInfos.size(); i++) {
        builder.addKeyInfo(keyInfoFromJson(keyInfos.get(i).getAsJsonObject()));
      }
    }
    return builder.build();
  }

  private static KeysetInfo.KeyInfo keyInfoFromJson(JsonObject json) throws IOException {
    return KeysetInfo.KeyInfo.newBuilder()
        .setStatus(getStatus(json.get("status").getAsString()))
        .setKeyId(getKeyId(json.get("keyId")))
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
