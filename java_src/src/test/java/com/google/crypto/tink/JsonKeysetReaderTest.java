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

import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Hex;
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
    TinkConfig.register();
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
    KeysetHandle handle1 = KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, JsonKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testRead_multipleKeys_shouldWork() throws Exception {
    KeysetHandle handle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId())
            .build();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CleartextKeysetHandle.write(handle1, JsonKeysetWriter.withOutputStream(outputStream));
    KeysetHandle handle2 =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())));

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void readTestKeysetVerifyTestTag() throws Exception {
    KeysetHandle handle = CleartextKeysetHandle.read(JsonKeysetReader.withString(JSON_KEYSET));
    byte[] data = "data".getBytes(UTF_8);
    Mac mac = handle.getPrimitive(Mac.class);
    byte[] tag = Hex.decode("0120a4107f3549e4fb3137415a63f5c8a0524f8ca7");
    mac.verifyMac(tag, data);
  }

  @Test
  public void readEncryptedTestKeysetVerifyTestTag() throws Exception {
    // This is the same test vector as in KeysetHandleTest.
    // An AEAD key, with which we encrypted the mac keyset below.
    byte[] serializedKeysetEncryptionKeyset =
        Hex.decode(
            "08b891f5a20412580a4c0a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e6372797"
                + "0746f2e74696e6b2e4165734561784b65791216120208101a10e5d7d0cdd649e81e7952260689b2"
                + "e1971801100118b891f5a2042001");
    KeysetHandle keysetEncryptionHandle = TinkProtoKeysetFormat.parseKeyset(
        serializedKeysetEncryptionKeyset, InsecureSecretKeyAccess.get());
    Aead keysetEncryptionAead = keysetEncryptionHandle.getPrimitive(Aead.class);
    byte[] associatedData = Hex.decode("abcdef330012");

    String encryptedKeyset =
        "{\"encryptedKeyset\":"
            + "\"AURdSLhZcFEgMBptDyi4/D8hL3h+Iz7ICgLrdeVRH26Fi3uSeewFoFA5cV5wfNueme3/BBR60yJ4hGpQ"
            + "p+/248ZIgfuWyfmAGZ4dmYnYC1qd/IWkZZfVr3aOsx4j4kFZHkkvA+XIZUh/INbdPsMUNJy9cmu6s8osdH"
            + "zu0XzP2ltWUowbr0fLQJwy92eAvU6gv91k6Tc=\","
            + "\"keysetInfo\":{\"primaryKeyId\":547623039,\"keyInfo\":[{\"typeUrl\":"
            + "\"type.googleapis.com/google.crypto.tink.HmacKey\",\"status\":\"ENABLED\","
            + "\"keyId\":547623039,\"outputPrefixType\":\"TINK\"}]}}";

    KeysetHandle handle = KeysetHandle.readWithAssociatedData(
        JsonKeysetReader.withString(encryptedKeyset), keysetEncryptionAead, associatedData);
    byte[] data = "data".getBytes(UTF_8);
    Mac mac = handle.getPrimitive(Mac.class);
    byte[] tag = Hex.decode("0120a4107f3549e4fb3137415a63f5c8a0524f8ca7");
    mac.verifyMac(tag, data);
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
    KeysetHandle handle1 = KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
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
    Aead masterKey =
        KeysetHandle.generateNew(PredefinedAeadParameters.AES128_EAX).getPrimitive(Aead.class);
    KeysetHandle handle1 = KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
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
    Aead keysetEncryptionAead =
        KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX")).getPrimitive(Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetHandle handle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG")
                    .withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_128BITTAG_RAW")
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG")
                    .withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG_RAW")
                    .withRandomId()
                    .setStatus(KeyStatus.DESTROYED))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId()
                    .setStatus(KeyStatus.DISABLED))
            .build();
    handle1.write(JsonKeysetWriter.withOutputStream(outputStream), keysetEncryptionAead);
    KeysetHandle handle2 =
        KeysetHandle.read(
            JsonKeysetReader.withInputStream(new ByteArrayInputStream(outputStream.toByteArray())),
            keysetEncryptionAead);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadEncrypted_missingKeysetInfo_shouldSucceed() throws Exception {
    Aead keysetEncryptionAead =
        KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX")).getPrimitive(Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetHandle handle1 = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_128BITTAG"));

    // Generate a valid encrypted keyset in JSON format, and delete "keysetInfo".
    handle1.write(JsonKeysetWriter.withOutputStream(outputStream), keysetEncryptionAead);
    JsonObject jsonEncryptedKeyset =
        JsonParser.parseString(new String(outputStream.toByteArray(), UTF_8)).getAsJsonObject();
    jsonEncryptedKeyset.remove("keysetInfo");
    String jsonEncryptedKeysetWithoutKeysetInfo = jsonEncryptedKeyset.toString();

    KeysetHandle handle2 =
        KeysetHandle.read(
            JsonKeysetReader.withString(jsonEncryptedKeysetWithoutKeysetInfo),
            keysetEncryptionAead);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void testReadEncrypted_missingEncryptedKeyset_shouldThrowException() throws Exception {
    Aead masterKey =
        KeysetHandle.generateNew(PredefinedAeadParameters.AES128_EAX).getPrimitive(Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetHandle handle = KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
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
    Aead masterKey =
        KeysetHandle.generateNew(PredefinedAeadParameters.AES128_EAX).getPrimitive(Aead.class);
    KeysetHandle handle1 = KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    handle1.write(JsonKeysetWriter.withOutputStream(outputStream), masterKey);
    KeysetHandle handle2 =
        KeysetHandle.read(JsonKeysetReader.withBytes(outputStream.toByteArray()), masterKey);

    assertKeysetHandle(handle1, handle2);
  }

  @Test
  public void readKeyset_negativeKeyId_works() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("-21");
    Keyset keyset = JsonKeysetReader.withString(jsonKeysetString).read();
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(-21);
  }

  @Test
  public void readKeyset_convertsUnsignedUint32IntoSignedInt32() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("4294967275"); // 2^32 - 21
    Keyset keyset = JsonKeysetReader.withString(jsonKeysetString).read();
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(-21);
  }

  @Test
  public void readKeyset_acceptsMaxUint32() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("4294967295"); // 2^32 - 1 = 0xffffffff
    Keyset keyset = JsonKeysetReader.withString(jsonKeysetString).read();
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(-1);
  }

  @Test
  public void readKeyset_acceptsMinInt32() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("-2147483648"); // - 2^31
    Keyset keyset = JsonKeysetReader.withString(jsonKeysetString).read();
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(-2147483648);
  }

  @Test
  public void readKeyset_rejectsKeyIdLargerThanUint32() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("4294967296"); // 2^32
    assertThrows(IOException.class, () -> JsonKeysetReader.withString(jsonKeysetString).read());
  }

  @Test
  public void readKeyset_rejectsKeyIdLargerThanUint64() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("18446744073709551658"); // 2^64 + 42
    assertThrows(IOException.class, () -> JsonKeysetReader.withString(jsonKeysetString).read());
  }

  @Test
  public void readKeyset_rejectsKeyIdSmallerThanInt32() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("-2147483649"); // - 2^31 - 1
    assertThrows(IOException.class, () -> JsonKeysetReader.withString(jsonKeysetString).read());
  }

  @Test
  public void testReadKeyset_keyIdWithComment_throws() throws Exception {
    String jsonKeysetString = createJsonKeysetWithId("123 /* comment on key ID */");
    assertThrows(IOException.class, () -> JsonKeysetReader.withString(jsonKeysetString).read());
  }

  @Test
  public void testReadKeyset_withDuplicatedMapKey_throws() throws Exception {
    String jsonKeysetString = "{"
        + "\"primaryKeyId\": 123,"
        + "\"key\": [{"
        + "\"keyData\": {"
        + "\"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\","
        + "\"keyMaterialType\": \"SYMMETRIC\","
        + "\"keyMaterialType\": \"SYMMETRIC\","
        + "\"value\": \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac+bwFOGSkENGmU+1EYgocg==\""
        + "},"
        + "\"outputPrefixType\": \"TINK\","
        + "\"keyId\": 123,"
        + "\"status\": \"ENABLED\""
        + "}]}";
    assertThrows(IOException.class, () -> JsonKeysetReader.withString(jsonKeysetString).read());
  }

  @Test
  public void testReadKeyset_withInvalidCharacterInTypeUrl_throws() throws Exception {
    String jsonKeysetString =
        "{"
            + "\"primaryKeyId\": 123,"
            + "\"key\": [{"
            + "\"keyData\": {"
            + "\"typeUrl\": \"type.googleapis.com/google.crypto.tink.HmacKey\\uD834\","
            + "\"keyMaterialType\": \"SYMMETRIC\","
            + "\"value\": \"EgQIAxAQGiBYhMkitTWFVefTIBg6kpvac+bwFOGSkENGmU+1EYgocg==\""
            + "},"
            + "\"outputPrefixType\": \"TINK\","
            + "\"keyId\": 123,"
            + "\"status\": \"ENABLED\""
            + "}]}";
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
