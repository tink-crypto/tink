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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Config;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.ChaCha20Poly1305Key;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for ChaCha20Poly1305KeyManager. */
@RunWith(JUnit4.class)
public class ChaCha20Poly1305KeyManagerTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    Config.register(AeadConfig.TINK_1_0_0);
  }

  @Test
  public void testBasic() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.CHACHA20_POLY1305);
    TestUtil.runBasicAeadFactoryTests(keysetHandle);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.CHACHA20_POLY1305);
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + 12 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */,
        ciphertext.length);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    KeyTemplate keyTemplate = AeadKeyTemplates.CHACHA20_POLY1305;
    ChaCha20Poly1305KeyManager keyManager = new ChaCha20Poly1305KeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 10;
    for (int i = 0; i < numTests; i++) {
      ChaCha20Poly1305Key key = (ChaCha20Poly1305Key) keyManager.newKey(keyTemplate.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(32, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = ChaCha20Poly1305Key.parseFrom(keyData.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(32, key.getKeyValue().toByteArray().length);
    }
    assertEquals(numTests * 2, keys.size());
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    ChaCha20Poly1305KeyManager keyManager = new ChaCha20Poly1305KeyManager();

    // Prepare example keys.
    int keyCount = 4;
    ChaCha20Poly1305Key[] keys = new ChaCha20Poly1305Key[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        // Passing any proto as a parameter for newKey, as the manager doesn't use that parameter.
        keys[i] = (ChaCha20Poly1305Key) keyManager.newKey(AeadKeyTemplates.CHACHA20_POLY1305);
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for i="  + i);
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (ChaCha20Poly1305Key key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        ChaCha20Poly1305Key keyFromJson = (ChaCha20Poly1305Key) keyManager.jsonToKey(json);
        assertEquals(key.toString(), keyFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for key: " + key.toString());
      }
      count++;
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    ChaCha20Poly1305KeyManager keyManager = new ChaCha20Poly1305KeyManager();

    // Check handling of key format protos.
    try {
      keyManager.keyFormatToJson(null);
      fail("Operation not supported, should have thrown exception.");
    } catch (Exception e) {
      // Expected.
      assertExceptionContains(e, "not supported");
    }

    try {
      keyManager.jsonToKeyFormat(null);
      fail("Operation not supported, should have thrown exception.");
    } catch (Exception e) {
      // Expected.
      assertExceptionContains(e, "not supported");
    }

    try {  // Incorrect JSON.
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      ChaCha20Poly1305Key key = (ChaCha20Poly1305Key) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0 }}".getBytes(Util.UTF_8);
      ChaCha20Poly1305Key key = (ChaCha20Poly1305Key) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0}, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      ChaCha20Poly1305Key key = (ChaCha20Poly1305Key) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete ChaCha20Poly1305Key.
      ChaCha20Poly1305Key key = ChaCha20Poly1305Key.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete ChaCha20Poly1305Key, should have thrown exception");
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
  }
}
