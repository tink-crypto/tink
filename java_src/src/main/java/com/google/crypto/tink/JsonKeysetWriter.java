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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
      outputStream.write(toJson(keyset).toString(4).getBytes(UTF_8));
      outputStream.write(System.lineSeparator().getBytes(UTF_8));
    } catch (JSONException e) {
      throw new IOException(e);
    } finally {
      outputStream.close();
    }
  }

  @Override
  public void write(EncryptedKeyset keyset) throws IOException {
    try {
      outputStream.write(toJson(keyset).toString(4).getBytes(UTF_8));
      outputStream.write(System.lineSeparator().getBytes(UTF_8));
    } catch (JSONException e) {
      throw new IOException(e);
    } finally {
      outputStream.close();
    }
  }

  private long toUnsignedLong(int x) {
    return ((long) x) & 0xffffffffL;
  }

  private JSONObject toJson(Keyset keyset) throws JSONException {
    JSONObject json = new JSONObject();
    json.put("primaryKeyId", toUnsignedLong(keyset.getPrimaryKeyId()));
    JSONArray keys = new JSONArray();
    for (Keyset.Key key : keyset.getKeyList()) {
      keys.put(toJson(key));
    }
    json.put("key", keys);
    return json;
  }

  private JSONObject toJson(Keyset.Key key) throws JSONException {
    return new JSONObject()
        .put("keyData", toJson(key.getKeyData()))
        .put("status", key.getStatus().name())
        .put("keyId", toUnsignedLong(key.getKeyId()))
        .put("outputPrefixType", key.getOutputPrefixType().name());
  }

  private JSONObject toJson(KeyData keyData) throws JSONException {
    return new JSONObject()
        .put("typeUrl", keyData.getTypeUrl())
        .put("value", Base64.encode(keyData.getValue().toByteArray()))
        .put("keyMaterialType", keyData.getKeyMaterialType().name());
  }

  private JSONObject toJson(EncryptedKeyset keyset) throws JSONException {
    return new JSONObject()
        .put("encryptedKeyset", Base64.encode(keyset.getEncryptedKeyset().toByteArray()))
        .put("keysetInfo", toJson(keyset.getKeysetInfo()));
  }

  private JSONObject toJson(KeysetInfo keysetInfo) throws JSONException {
    JSONObject json = new JSONObject();
    json.put("primaryKeyId", toUnsignedLong(keysetInfo.getPrimaryKeyId()));
    JSONArray keyInfos = new JSONArray();
    for (KeysetInfo.KeyInfo keyInfo : keysetInfo.getKeyInfoList()) {
      keyInfos.put(toJson(keyInfo));
    }
    json.put("keyInfo", keyInfos);
    return json;
  }

  private JSONObject toJson(KeysetInfo.KeyInfo keyInfo) throws JSONException {
    return new JSONObject()
        .put("typeUrl", keyInfo.getTypeUrl())
        .put("status", keyInfo.getStatus().name())
        .put("keyId", keyInfo.getKeyId())
        .put("outputPrefixType", keyInfo.getOutputPrefixType().name());
  }
}
