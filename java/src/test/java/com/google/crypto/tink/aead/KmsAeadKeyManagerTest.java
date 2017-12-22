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

package com.google.crypto.tink.aead;

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KmsAeadKey;
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KmsAeadKeyManager. */
@RunWith(JUnit4.class)
public class KmsAeadKeyManagerTest {
  @Before
  public void setUp() throws Exception {
    KmsClient kmsClient = new GcpKmsClient().withCredentials(TestUtil.SERVICE_ACCOUNT_FILE);
    KmsClients.add(kmsClient);
    Config.register(AeadConfig.TINK_1_0_0);
  }

  @Test
  public void testGcpKmsKeyRestricted() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(
            AeadKeyTemplates.createKmsAeadKeyTemplate(TestUtil.RESTRICTED_CRYPTO_KEY_URI));
    TestUtil.runBasicAeadFactoryTests(keysetHandle);
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    KmsAeadKeyManager keyManager = new KmsAeadKeyManager();
    int keyCount = 1;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = AeadKeyTemplates.createKmsAeadKeyTemplate(
        TestUtil.RESTRICTED_CRYPTO_KEY_URI).getValue();

    KmsAeadKey[] keys = new KmsAeadKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (KmsAeadKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString()
            + "\nFailed for formats[" + i + "]: " + formats[i].toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (KmsAeadKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        KmsAeadKey keyFromJson = (KmsAeadKey) keyManager.jsonToKey(json);
        assertEquals(key.toString(), keyFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for key: " + key.toString());
      }
      count++;
    }
    assertEquals(keyCount, count);

    // Check export and import of key formats.
    count = 0;
    for (ByteString format : formats) {
      try {
        byte[] json = keyManager.keyFormatToJson(format);
        KmsAeadKeyFormat formatFromJson = (KmsAeadKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(KmsAeadKeyFormat.parseFrom(format).toString(), formatFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format: " + format.toString());
      }
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    KmsAeadKeyManager keyManager = new KmsAeadKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      KmsAeadKey key = (KmsAeadKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      KmsAeadKeyFormat format = (KmsAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0}".getBytes(Util.UTF_8);
      KmsAeadKey key = (KmsAeadKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{}".getBytes(Util.UTF_8);
      KmsAeadKeyFormat format = (KmsAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"keyUri\": \"some URI\"}, "
          + "\"extraName\": 42}").getBytes(Util.UTF_8);
      KmsAeadKey key = (KmsAeadKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"keyUri\": \"some URI\", \"extraName\": 42}").getBytes(Util.UTF_8);
      KmsAeadKeyFormat format = (KmsAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Incomplete params in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {}}").getBytes(Util.UTF_8);
      KmsAeadKey key = (KmsAeadKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // Extra name in JSON key params.
      byte[] json = ("{\"params\": {\"keyUri\": \"some URI\", \"extraName\": 42}, "
          + "\"version\": 0}").getBytes(Util.UTF_8);
      KmsAeadKey key = (KmsAeadKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // An incomplete KmsAeadKey.
      KmsAeadKey key = KmsAeadKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete KmsAeadKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete KmsAeadKeyFormat.
      KmsAeadKeyFormat format = KmsAeadKeyFormat.newBuilder().build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete KmsAeadKeyFormat, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // Wrong serialized key proto.
      KeyData key = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Wrong key proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized KmsAeadKey");
    }

    try {  // Wrong serialized key format proto.
      KmsAeadKey format = KmsAeadKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }
  }
}
