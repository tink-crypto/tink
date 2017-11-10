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
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.KeysetInfo.KeyInfo;
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
 * A {@link KeysetWriter} that can write to some source cleartext or encrypted keysets in proto JSON
 * format.
 */
public final class JsonKeysetWriter implements KeysetWriter {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  private final OutputStream outputStream;

  private JsonKeysetWriter(OutputStream stream) {
    outputStream = stream;
  }

  public static KeysetWriter withOutputStream(OutputStream stream) {
    return new JsonKeysetWriter(stream);
  }

  public static KeysetWriter withFile(File file) throws IOException {
    return new JsonKeysetWriter(new FileOutputStream(file));
  }

  public static KeysetWriter withPath(String path) throws IOException {
    return withFile(new File(path));
  }

  public static KeysetWriter withPath(Path path) throws IOException {
    return withFile(path.toFile());
  }

  @Override
  public void write(Keyset keyset) throws IOException {
    try {
      outputStream.write(toJson(keyset).toString(4).getBytes(UTF_8));
    } catch (JSONException e) {
      throw new IOException(e);
    }
  }

  @Override
  public void write(EncryptedKeyset keyset) throws IOException {
    try {
      outputStream.write(toJson(keyset).toString(4).getBytes(UTF_8));
    } catch (JSONException e) {
      throw new IOException(e);
    }
  }

  private JSONObject toJson(Keyset keyset) throws JSONException {
    JSONObject json = new JSONObject();
    json.put("primaryKeyId", keyset.getPrimaryKeyId());
    JSONArray keys = new JSONArray();
    for (Key key : keyset.getKeyList()) {
      keys.put(toJson(key));
    }
    json.put("key", keys);
    return json;
  }

  private JSONObject toJson(Key key) throws JSONException {
    return new JSONObject()
        .put("keyData", toJson(key.getKeyData()))
        .put("status", key.getStatus().toString())
        .put("keyId", key.getKeyId())
        .put("outputPrefixType", key.getOutputPrefixType().toString());
  }

  private JSONObject toJson(KeyData keyData) throws JSONException {
    return new JSONObject()
        .put("typeUrl", keyData.getTypeUrl())
        .put("value", Base64.encode(keyData.getValue().toByteArray()))
        .put("keyMaterialType", keyData.getKeyMaterialType().toString());
  }

  private JSONObject toJson(EncryptedKeyset keyset) throws JSONException {
    return new JSONObject()
        .put("encryptedKeyset", Base64.encode(keyset.getEncryptedKeyset().toByteArray()))
        .put("keysetInfo", toJson(keyset.getKeysetInfo()));
  }

  private JSONObject toJson(KeysetInfo keysetInfo) throws JSONException {
    JSONObject json = new JSONObject();
    json.put("primaryKeyId", keysetInfo.getPrimaryKeyId());
    JSONArray keyInfos = new JSONArray();
    for (KeyInfo keyInfo : keysetInfo.getKeyInfoList()) {
      keyInfos.put(toJson(keyInfo));
    }
    json.put("keyInfo", keyInfos);
    return json;
  }

  private JSONObject toJson(KeyInfo keyInfo) throws JSONException {
    return new JSONObject()
        .put("typeUrl", keyInfo.getTypeUrl())
        .put("status", keyInfo.getStatus().toString())
        .put("keyId", keyInfo.getKeyId())
        .put("outputPrefixType", keyInfo.getOutputPrefixType().toString());
  }
}
