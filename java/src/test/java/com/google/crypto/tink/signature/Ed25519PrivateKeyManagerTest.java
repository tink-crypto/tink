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

package com.google.crypto.tink.signature;

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Ed25519PrivateKeyManager. */
@RunWith(JUnit4.class)
public class Ed25519PrivateKeyManagerTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    Config.register(SignatureConfig.TINK_1_0_0);
    ;
  }

  @Test
  public void testBasic() throws Exception {
    Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
    KeyTemplate template = SignatureKeyTemplates.ED25519;
    MessageLite key = manager.newKey(template);
    assertTrue(key instanceof Ed25519PrivateKey);

    Ed25519PrivateKey keyProto = (Ed25519PrivateKey) key;
    assertEquals(32, keyProto.getKeyValue().size());

    PublicKeySign signer = manager.getPrimitive(key);
    assertTrue(signer instanceof Ed25519Sign);
    byte[] message = Random.randBytes(20);
    byte[] signature = signer.sign(message);
    assertEquals(64, signature.length);

    Ed25519PublicKeyManager publicKeyManager = new Ed25519PublicKeyManager();
    PublicKeyVerify verifier = publicKeyManager.getPrimitive(keyProto.getPublicKey());
    assertTrue(verifier instanceof Ed25519Verify);
    try {
      verifier.verify(signature, message);
    } catch (GeneralSecurityException e) {
      fail("Do not expect GeneralSecurityException: " + e);
    }
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  public void testGetPublicKeyData() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ED25519);
    KeyData privateKeyData = TestUtil.getKeyset(privateHandle).getKey(0).getKeyData();
    Ed25519PrivateKeyManager privateManager = new Ed25519PrivateKeyManager();
    KeyData publicKeyData = privateManager.getPublicKeyData(privateKeyData.getValue());
    assertEquals(Ed25519PublicKeyManager.TYPE_URL, publicKeyData.getTypeUrl());
    assertEquals(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC, publicKeyData.getKeyMaterialType());
    Ed25519PrivateKey privateKey = Ed25519PrivateKey.parseFrom(privateKeyData.getValue());
    assertArrayEquals(
        privateKey.getPublicKey().toByteArray(), publicKeyData.getValue().toByteArray());

    Ed25519PublicKeyManager publicManager = new Ed25519PublicKeyManager();
    PublicKeySign signer = privateManager.getPrimitive(privateKeyData.getValue());
    PublicKeyVerify verifier = publicManager.getPrimitive(publicKeyData.getValue());
    byte[] message = Random.randBytes(20);
    try {
      verifier.verify(signer.sign(message), message);
    } catch (GeneralSecurityException e) {
      fail("Should not fail: " + e);
    }
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    Ed25519PrivateKeyManager keyManager = new Ed25519PrivateKeyManager();
    int keyCount = 4;

    // Prepare example keys.
    Ed25519PrivateKey[] keys = new Ed25519PrivateKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
     try {
        // Passing any proto as a parameter for newKey, as the manager doesn't use that parameter.
        keys[i] = (Ed25519PrivateKey) keyManager.newKey(SignatureKeyTemplates.ED25519);
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for i="  + i);
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (Ed25519PrivateKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        Ed25519PrivateKey keyFromJson = (Ed25519PrivateKey) keyManager.jsonToKey(json);
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
    Ed25519PrivateKeyManager keyManager = new Ed25519PrivateKeyManager();

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
      Ed25519PrivateKey key = (Ed25519PrivateKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0, \"keyValue\": \"some key bytes\"}".getBytes(Util.UTF_8);
      Ed25519PrivateKey key = (Ed25519PrivateKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"publicKey\": {}, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      Ed25519PrivateKey key = (Ed25519PrivateKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Incomplete public key in JSON key.
      byte[] json = ("{\"version\": 0, \"publicKey\": {\"version\": 42}, "
          + "\"keyValue\": \"some key bytes\"}").getBytes(Util.UTF_8);
      Ed25519PrivateKey key = (Ed25519PrivateKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete Ed25519PrivateKey.
      Ed25519PrivateKey key = Ed25519PrivateKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete Ed25519PrivateKey, should have thrown exception");
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
