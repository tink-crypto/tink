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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Random;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JsonKeysetReader. */
@RunWith(JUnit4.class)
public class JsonKeysetReaderTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  private static String createJsonKeysetWithId(String id) {
    return "{"
        + ("\"primaryKeyId\": " + id + ",")
        + "\"key\": [{"
        + "\"keyData\": {"
        + "\"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
        + "\"keyMaterialType\": \"SYMMETRIC\","
        + "\"value\": \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac+bwFOGSkENGmU+1EYgocg==\""
        + "},"
        + "\"outputPrefixType\": \"TINK\","
        + ("\"keyId\": " + id + ",")
        + "\"status\": \"ENABLED\""
        + "}]}";
  }

  private static final String JSON_KEYSET = createJsonKeysetWithId("547623039");

  private static final String URL_SAFE_JSON_KEYSET =
      "{"
          + "\"primaryKeyId\": 547623039,"
          + "\"key\": [{"
          + "\"keyData\": {"
          + "\"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
          + "\"keyMaterialType\": \"SYMMETRIC\","
          + "\"value\": \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac-bwFOGSkENGmU-1EYgocg\""
          + "},"
          + "\"outputPrefixType\": \"TINK\","
          + "\"keyId\": 547623039,"
          + "\"status\": \"ENABLED\""
          + "}]}";

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    Config.register(TinkConfig.TINK_1_0_0);
  }

  private void assertKeysetHandle(KeysetHandle handle1, KeysetHandle handle2) throws Exception {
    Mac mac1 = handle1.getPrimitive(Mac.class);
    Mac mac2 = handle2.getPrimitive(Mac.class);
    byte[] message = Random.randBytes(20);

    assertThat(handle2.getKeyset()).isEqualTo(handle1.getKeyset());
    mac2.verifyMac(mac1.computeMac(message), message);
  }

  @Test
  public void testRead_singleKey_shouldWork() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle1 = KeysetHandle.generateNew(template);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, JsonKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testRead_multipleKeys_shouldWork() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle1 =
        KeysetManager.withEmptyKeyset()
            .rotate(template)
            .add(template)
            .add(template)
            .getKeysetHandle();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, JsonKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testRead_urlSafeKeyset_shouldWork() throws Exception {
    KeysetHandle handle1 = CleartextKeysetHandle.read(JsonKeysetReader.withString(JSON_KEYSET));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withString(URL_SAFE_JSON_KEYSET).withUrlSafeBase64());

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testRead_missingKey_shouldThrowException() throws Exception {
    JsonObject json = JsonParser.parseString(JSON_KEYSET).getAsJsonObject();
    json.remove("key"); // remove key

    IOException e =
        assertThrows(IOException.class, () -> JsonKeysetReader.withJsonObject(json).read());
    assertThat(e.toString()).contains("invalid keyset");
  }

  private void testRead_invalidKey_shouldThrowException(String name) throws Exception {
    JsonObject json = JsonParser.parseString(JSON_KEYSET).getAsJsonObject();
    JsonArray keys = json.get("key").getAsJsonArray();
    JsonObject key = keys.get(0).getAsJsonObject();
    key.remove(name);
    keys.set(0, key);
    json.add("key", keys);

    try {
      JsonKeysetReader.withJsonObject(json).read();
      fail("Expected IOException");
    } catch (IOException e) {
      assertThat(e.toString()).contains("invalid key");
    }
  }

  @Test
  public void testRead_invalidKey_shouldThrowException() throws Exception {
    testRead_invalidKey_shouldThrowException("keyData");
    testRead_invalidKey_shouldThrowException("status");
    testRead_invalidKey_shouldThrowException("keyId");
    testRead_invalidKey_shouldThrowException("outputPrefixType");
  }

  private void testRead_invalidKeyData_shouldThrowException(String name) throws Exception {
    JsonObject json = JsonParser.parseString(JSON_KEYSET).getAsJsonObject();
    JsonArray keys = json.get("key").getAsJsonArray();
    JsonObject key = keys.get(0).getAsJsonObject();
    JsonObject keyData = key.get("keyData").getAsJsonObject();
    keyData.remove(name);
    key.add("keyData", keyData);
    keys.set(0, key);
    json.add("key", keys);

    try {
      JsonKeysetReader.withJsonObject(json).read();
      fail("Expected IOException");
    } catch (IOException e) {
      assertThat(e.toString()).contains("invalid keyData");
    }
  }

  @Test
  public void testRead_invalidKeyData_shouldThrowException() throws Exception {
    testRead_invalidKeyData_shouldThrowException("typeUrl");
    testRead_invalidKeyData_shouldThrowException("value");
    testRead_invalidKeyData_shouldThrowException("keyMaterialType");
  }

  @Test
  public void testRead_invalidKeyMaterialType_shouldThrowException() throws Exception {
    JsonObject json = JsonParser.parseString(JSON_KEYSET).getAsJsonObject();
    JsonArray keys = json.get("key").getAsJsonArray();
    JsonObject key = keys.get(0).getAsJsonObject();
    JsonObject keyData = key.get("keyData").getAsJsonObject();
    keyData.addProperty("keyMaterialType", "invalid");
    key.add("keyData", keyData);
    keys.set(0, key);
    json.add("key", keys);

    IOException e =
        assertThrows(IOException.class, () -> JsonKeysetReader.withJsonObject(json).read());
    assertThat(e.toString()).contains("unknown key material type");
  }

  @Test
  public void testRead_invalidStatus_shouldThrowException() throws Exception {
    JsonObject json = JsonParser.parseString(JSON_KEYSET).getAsJsonObject();
    JsonArray keys = json.get("key").getAsJsonArray();
    JsonObject key = keys.get(0).getAsJsonObject();
    key.addProperty("status", "invalid");
    keys.set(0, key);
    json.add("key", keys);

    IOException e =
        assertThrows(IOException.class, () -> JsonKeysetReader.withJsonObject(json).read());
    assertThat(e.toString()).contains("unknown status");
  }

  @Test
  public void testRead_invalidOutputPrefixType_shouldThrowException() throws Exception {
    JsonObject json = JsonParser.parseString(JSON_KEYSET).getAsJsonObject();
    JsonArray keys = json.get("key").getAsJsonArray();
    JsonObject key = keys.get(0).getAsJsonObject();
    key.addProperty("outputPrefixType", "invalid");
    keys.set(0, key);
    json.add("key", keys);

    IOException e =
        assertThrows(IOException.class, () -> JsonKeysetReader.withJsonObject(json).read());
    assertThat(e.toString()).contains("unknown output prefix type");
  }

  @Test
  public void testRead_jsonKeysetWriter_shouldWork() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle1 = KeysetHandle.generateNew(template);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, JsonKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(JsonKeysetReader.withBytes(outputStream.toByteArray()));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testRead_staticMethods_validKeyset_shouldWork() throws Exception {
    KeysetHandle handle1 = CleartextKeysetHandle.read(JsonKeysetReader.withString(JSON_KEYSET));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withInputStream(
                new ByteArrayInputStream(JSON_KEYSET.getBytes(UTF_8))));
    KeysetHandle handle3 =
        CleartextKeysetHandle.read(JsonKeysetReader.withBytes(JSON_KEYSET.getBytes(UTF_8)));
    KeysetHandle handle4 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withJsonObject(JsonParser.parseString(JSON_KEYSET).getAsJsonObject()));

    assertKeysetHandle(handle1, handle2);
    assertKeysetHandle(handle1, handle3);
    assertKeysetHandle(handle1, handle4);
  }

  @Test
  public void testReadEncrypted_singleKey_shouldWork() throws Exception {
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_EAX;
    Aead masterKey = Registry.getPrimitive(Registry.newKeyData(masterKeyTemplate));
    KeysetHandle handle1 = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle1.write(JsonKeysetWriter.withOutputStream(outputStream), masterKey);
    KeysetHandle handle2 =
        KeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())),
            masterKey);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadEncrypted_multipleKeys_shouldWork() throws Exception {
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_EAX;
    Aead masterKey = Registry.getPrimitive(Registry.newKeyData(masterKeyTemplate));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle1 =
        KeysetManager.withEmptyKeyset()
            .rotate(template)
            .add(template)
            .add(template)
            .getKeysetHandle();
    handle1.write(JsonKeysetWriter.withOutputStream(outputStream), masterKey);
    KeysetHandle handle2 =
        KeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())),
            masterKey);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadEncrypted_missingEncryptedKeyset_shouldThrowException() throws Exception {
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_EAX;
    Aead masterKey = Registry.getPrimitive(Registry.newKeyData(masterKeyTemplate));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetHandle handle = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    handle.write(JsonKeysetWriter.withOutputStream(outputStream), masterKey);
    JsonObject json =
        JsonParser.parseString(new String(outputStream.toByteArray(), UTF_8)).getAsJsonObject();
    json.remove("encryptedKeyset"); // remove key

    IOException e =
        assertThrows(
            IOException.class, () -> JsonKeysetReader.withJsonObject(json).readEncrypted());
    assertThat(e.toString()).contains("invalid encrypted keyset");
  }

  @Test
  public void testReadEncrypted_jsonKeysetWriter_shouldWork() throws Exception {
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_EAX;
    Aead masterKey = Registry.getPrimitive(Registry.newKeyData(masterKeyTemplate));
    KeysetHandle handle1 = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle1.write(JsonKeysetWriter.withOutputStream(outputStream), masterKey);
    KeysetHandle handle2 =
        KeysetHandle.read(JsonKeysetReader.withBytes(outputStream.toByteArray()), masterKey);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadKeyset_negativeKeyId_works() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("-21");
    Keyset keyset = JsonKeysetReader.withString(jsonKeysetString).read();
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(-21);
  }

  @Test
  public void testReadKeyset_hugeKeyId_convertsIntoSignedInt32() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("4294967275"); // 2^32 - 21
    Keyset keyset = JsonKeysetReader.withString(jsonKeysetString).read();
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(-21);
  }

  @Test
  public void testReadKeyset_keyIdWithComment_throws() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("123 /* comment on key ID */");
    assertThrows(IOException.class, () -> JsonKeysetReader.withString(jsonKeysetString).read());
  }

  @Test
  public void testReadKeyset_withoutQuotes_throws() throws Exception {
    String jsonKeysetString = "{"
        + "primaryKeyId: 123,"
        + "key:[{"
        + "keyData:{"
        + "typeUrl:\"type.googleapis.com/google.crypto.tink.HmacKey\","
        + "keyMaterialType: SYMMETRIC,"
        + "value: \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac+bwFOGSkENGmU+1EYgocg==\""
        + "},"
        + "outputPrefixType:TINK,"
        + "keyId:123,"
        + "status:ENABLED"
        + "}]}";
    assertThrows(IOException.class, () -> JsonKeysetReader.withString(jsonKeysetString).read());
  }
}
