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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Config;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Ed25519PublicKeyManager. */
@RunWith(JUnit4.class)
public class Ed25519PublicKeyManagerTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    Config.register(SignatureConfig.TINK_1_0_0);
  }

  @Test
  public void testModifiedSignature() throws Exception {
    Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
    KeyTemplate template = SignatureKeyTemplates.ED25519;
    MessageLite key = manager.newKey(template);
    Ed25519PrivateKey keyProto = (Ed25519PrivateKey) key;

    PublicKeySign signer = manager.getPrimitive(key);
    byte[] message = Random.randBytes(20);
    byte[] signature = signer.sign(message);
    Ed25519PublicKeyManager publicKeyManager = new Ed25519PublicKeyManager();
    PublicKeyVerify verifier = publicKeyManager.getPrimitive(keyProto.getPublicKey());
    try {
      verifier.verify(signature, message);
    } catch (GeneralSecurityException e) {
      fail("Did not expect GeneralSecurityException: " + e);
    }

    // Flip bits in message.
    for (int i = 0; i < message.length; i++) {
      byte[] copy = Arrays.copyOf(message, message.length);
      copy[i] = (byte) (copy[i] ^ 0xff);
      try {
        verifier.verify(signature, copy);
        fail("Expected GeneralSecurityException");
      } catch (GeneralSecurityException e) {
        assertExceptionContains(e, "Signature check failed.");
      }
    }

    // Flip bits in signature.
    // Flip the last byte.
    byte[] copySig = Arrays.copyOf(signature, signature.length);
    copySig[copySig.length - 1] = (byte) (copySig[copySig.length - 1] ^ 0xff);
    try {
      verifier.verify(copySig, message);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "Given signature's 3 most significant bits must be 0.");
    }
    // Flip other bytes.
    for (int i = 0; i < signature.length - 1; i++) {
      byte[] copy = Arrays.copyOf(signature, signature.length);
      copy[i] = (byte) (copy[i] ^ 0xff);
      try {
        verifier.verify(copy, message);
        fail("Expected GeneralSecurityException");
      } catch (GeneralSecurityException e) {
        assertExceptionContains(e, "Signature check failed.");
      }
    }
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    Ed25519PublicKeyManager keyManager = new Ed25519PublicKeyManager();
    int keyCount = 4;

    // Prepare example keys.
    Ed25519PublicKey[] keys = new Ed25519PublicKey[keyCount];
    Ed25519PrivateKeyManager privateKeyManager = new Ed25519PrivateKeyManager();
    for (int i = 0; i < keyCount; i++) {
     try {
        // Passing any proto as a parameter for newKey, as the manager doesn't use that parameter.
       keys[i] = ((Ed25519PrivateKey) privateKeyManager.newKey(SignatureKeyTemplates.ED25519))
           .getPublicKey();
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for i="  + i);
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (Ed25519PublicKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        Ed25519PublicKey keyFromJson = (Ed25519PublicKey) keyManager.jsonToKey(json);
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
    Ed25519PublicKeyManager keyManager = new Ed25519PublicKeyManager();

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
      Ed25519PublicKey key = (Ed25519PublicKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0}".getBytes(Util.UTF_8);
      Ed25519PublicKey key = (Ed25519PublicKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"key_value\": \"some key value\", "
          + "\"extraName\": 42}").getBytes(Util.UTF_8);
      Ed25519PublicKey key = (Ed25519PublicKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete Ed25519PublicKey.
      Ed25519PublicKey key = Ed25519PublicKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete Ed25519PublicKey, should have thrown exception");
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
