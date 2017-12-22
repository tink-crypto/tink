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

package com.google.crypto.tink.daead;

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AesSivKeyManager. */
@RunWith(JUnit4.class)
public class AesSivKeyManagerTest {
  private Integer[] keySizeInBytes;

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    DeterministicAeadConfig.init();
    Config.register(DeterministicAeadConfig.TINK_1_1_0);
  }

  @Before
  public void setUp2() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip all AesSivKeyManager tests");
      keySizeInBytes = new Integer[] {};
    } else if (TestUtil.isAndroid()) {
      keySizeInBytes = new Integer[] {64};
    } else {
      keySizeInBytes = new Integer[] {48, 64};
    }
  }

  @Test
  public void testCiphertextSize() throws Exception {
    for (int keySize : keySizeInBytes) {
      if (keySize == 48) {
        testCiphertextSize(DeterministicAeadKeyTemplates.AES192_SIV);
      } else if (keySize == 64) {
        testCiphertextSize(DeterministicAeadKeyTemplates.AES256_SIV);
      }
    }
  }

  private static void testCiphertextSize(KeyTemplate template) throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    DeterministicAead daead = DeterministicAeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length + 16 /* IV_SIZE */, ciphertext.length);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    for (int keySize : keySizeInBytes) {
      if (keySize == 48) {
        testNewKeyMultipleTimes(DeterministicAeadKeyTemplates.AES192_SIV);
      } else if (keySize == 64) {
        testNewKeyMultipleTimes(DeterministicAeadKeyTemplates.AES256_SIV);
      }
    }
  }

  private static void testNewKeyMultipleTimes(KeyTemplate keyTemplate) throws Exception {
    AesSivKeyManager keyManager = new AesSivKeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 10;
    for (int i = 0; i < numTests; i++) {
      AesSivKey key = (AesSivKey) keyManager.newKey(keyTemplate.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = AesSivKey.parseFrom(keyData.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
    }
    assertEquals(numTests * 2, keys.size());
  }

  @Test
  public void testNewKeyWithInvalidKeyFormats() throws Exception {
    AesSivKeyManager keyManager = new AesSivKeyManager();

    try {
      // AesSiv doesn't accept 32-byte keys.
      keyManager.newKey(createAesSivKeyFormat(32));
      fail("32-byte keys should not be accepted");
    } catch (InvalidAlgorithmParameterException ex) {
      // expected.
    }

    for (int j = 0; j < 100; j++) {
      if (j == 48 || j == 64) {
        continue;
      }

      try {
        keyManager.newKey(createAesSivKeyFormat(j));
        fail("Keys with invalid size should not be accepted: " + j);
      } catch (InvalidAlgorithmParameterException ex) {
        // expected.
      }
    }
  }

  @Test
  public void testGetPrimitiveWithInvalidKeys() throws Exception {
    AesSivKeyManager keyManager = new AesSivKeyManager();

    try {
      keyManager.getPrimitive(createAesSivKey(32));
      fail("32-byte keys should not be accepted");
    } catch (InvalidKeyException ex) {
      // expected.
    }

    for (int j = 0; j < 100; j++) {
      if (j == 48 || j == 64) {
        continue;
      }

      try {
        keyManager.getPrimitive(createAesSivKey(j));
        fail("Keys with invalid size should not be accepted: " + j);
      } catch (InvalidKeyException ex) {
        // expected.
      }
    }
  }

  private AesSivKeyFormat createAesSivKeyFormat(int keySize) {
    return AesSivKeyFormat.newBuilder().setKeySize(keySize).build();
  }

  private AesSivKey createAesSivKey(int keySize) {
    return AesSivKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(keySize)))
        .build();
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    AesSivKeyManager keyManager = new AesSivKeyManager();
    int keyCount = 2;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = DeterministicAeadKeyTemplates.AES192_SIV.getValue();
    formats[1] = DeterministicAeadKeyTemplates.AES256_SIV.getValue();

    AesSivKey[] keys = new AesSivKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (AesSivKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString()
            + "\nFailed for formats[" + i + "]: " + formats[i].toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (AesSivKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        AesSivKey keyFromJson = (AesSivKey) keyManager.jsonToKey(json);
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
        AesSivKeyFormat formatFromJson = (AesSivKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(AesSivKeyFormat.parseFrom(format).toString(), formatFromJson.toString());
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
    AesSivKeyManager keyManager = new AesSivKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      AesSivKey key = (AesSivKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      AesSivKeyFormat format = (AesSivKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0}".getBytes(Util.UTF_8);
      AesSivKey key = (AesSivKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{}".getBytes(Util.UTF_8);
      AesSivKeyFormat format = (AesSivKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      AesSivKey key = (AesSivKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"keySize\": 16, \"extraName\": 42}").getBytes(Util.UTF_8);
      AesSivKeyFormat format = (AesSivKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // An incomplete AesSivKey.
      AesSivKey key = AesSivKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete AesSivKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete AesSivKeyFormat.
      AesSivKeyFormat format = AesSivKeyFormat.newBuilder().build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete AesSivKeyFormat, should have thrown exception");
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
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }
  }
}
