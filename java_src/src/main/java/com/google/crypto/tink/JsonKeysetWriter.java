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
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.subtle.Base64;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;

/**
 * A {@link KeysetWriter} that can write to some source cleartext or encrypted keysets in <a
 * href="https://developers.google.com/protocol-buffers/docs/reference/java/com/google/protobuf/util/JsonFormat">proto
 * JSON format</a>.
 *
 * @since 1.0.0
 */
public final class JsonKeysetWriter implements KeysetWriter {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  private final OutputStream outputStream;

  private JsonKeysetWriter(OutputStream stream) {
    outputStream = stream;
  }

  /**
   * Static method to create a JsonKeysetWriter that writes to an {@link OutputStream}.
   *
   * <p>{@code stream} will be closed after the keyset is written.
   */
  public static KeysetWriter withOutputStream(OutputStream stream) {
    return new JsonKeysetWriter(stream);
  }

  /** Static method to create a JsonKeysetWriter that writes to a file. */
  public static KeysetWriter withFile(File file) throws IOException {
    return new JsonKeysetWriter(new FileOutputStream(file));
  }

  /** Static method to create a JsonKeysetWriter that writes to a file path. */
  public static KeysetWriter withPath(String path) throws IOException {
    return withFile(new File(path));
  }

  /**
   * Static method to create a JsonKeysetWriter that writes to a file path.
   *
   * <p>This method only works on Android API level 26 or newer.
   */
  public static KeysetWriter withPath(Path path) throws IOException {
    return withFile(path.toFile());
  }

  @Override
  public void write(Keyset keyset) throws IOException {
    try {
      outputStream.write(toJson(keyset).toString().getBytes(UTF_8));
      outputStream.write(System.lineSeparator().getBytes(UTF_8));
    } catch (JsonParseException e) {
      throw new IOException(e);
    } finally {
      outputStream.close();
    }
  }

  @Override
  public void write(EncryptedKeyset keyset) throws IOException {
    outputStream.write(toJson(keyset).toString().getBytes(UTF_8));
    outputStream.write(System.lineSeparator().getBytes(UTF_8));
    outputStream.close();
  }

  private long toUnsignedLong(int x) {
    return ((long) x) & 0xffffffffL;
  }

  private JsonObject toJson(Keyset keyset) {
    JsonObject json = new JsonObject();
    json.addProperty("primaryKeyId", toUnsignedLong(keyset.getPrimaryKeyId()));
    JsonArray keys = new JsonArray();
    for (Keyset.Key key : keyset.getKeyList()) {
      keys.add(toJson(key));
    }
    json.add("key", keys);
    return json;
  }

  private JsonObject toJson(Keyset.Key key) {
    JsonObject json = new JsonObject();
    json.add("keyData", toJson(key.getKeyData()));
    json.addProperty("status", key.getStatus().name());
    json.addProperty("keyId", toUnsignedLong(key.getKeyId()));
    json.addProperty("outputPrefixType", key.getOutputPrefixType().name());
    return json;
  }

  private JsonObject toJson(KeyData keyData) {
    JsonObject json = new JsonObject();
    json.addProperty("typeUrl", keyData.getTypeUrl());
    json.addProperty("value", Base64.encode(keyData.getValue().toByteArray()));
    json.addProperty("keyMaterialType", keyData.getKeyMaterialType().name());
    return json;
  }

  private JsonObject toJson(EncryptedKeyset keyset) {
    JsonObject json = new JsonObject();
    json.addProperty("encryptedKeyset", Base64.encode(keyset.getEncryptedKeyset().toByteArray()));
    json.add("keysetInfo", toJson(keyset.getKeysetInfo()));
    return json;
  }

  private JsonObject toJson(KeysetInfo keysetInfo) {
    JsonObject json = new JsonObject();
    json.addProperty("primaryKeyId", toUnsignedLong(keysetInfo.getPrimaryKeyId()));
    JsonArray keyInfos = new JsonArray();
    for (KeysetInfo.KeyInfo keyInfo : keysetInfo.getKeyInfoList()) {
      keyInfos.add(toJson(keyInfo));
    }
    json.add("keyInfo", keyInfos);
    return json;
  }

  private JsonObject toJson(KeysetInfo.KeyInfo keyInfo) {
    JsonObject json = new JsonObject();
    json.addProperty("typeUrl", keyInfo.getTypeUrl());
    json.addProperty("status", keyInfo.getStatus().name());
    json.addProperty("keyId", toUnsignedLong(keyInfo.getKeyId()));
    json.addProperty("outputPrefixType", keyInfo.getOutputPrefixType().name());
    return json;
  }
}
