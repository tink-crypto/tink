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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for EncryptedKeysetHandle.
 */
@RunWith(JUnit4.class)
public class EncryptedKeysetHandleTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    // Encrypt the keyset with an AeadKey.
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_GCM;
    Aead masterKey = Registry.INSTANCE.getPrimitive(
        Registry.INSTANCE.newKeyData(masterKeyTemplate));
    // Create a encrypted keyset that contains a single HmacKey.
    KeysetHandle handle = EncryptedKeysetHandle.generateNew(
        MacKeyTemplates.HMAC_SHA256_128BITTAG,
        masterKey);
    assertNotNull(handle.getEncryptedKeyset());
    KeysetHandle handle2 = EncryptedKeysetHandle.parseFrom(
        handle.getEncryptedKeyset(), masterKey);
    assertEquals(handle.getKeyset(), handle2.getKeyset());
  }

  @Test
  public void testWithExistingKeyset() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeysetHandle handle1 = new KeysetManager.Builder()
        .setKeyTemplate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
        .build()
        .rotate()
        .getKeysetHandle();

    // Encrypt the keyset with an AeadKey.
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_GCM;
    Aead masterKey = Registry.INSTANCE.getPrimitive(
        Registry.INSTANCE.newKeyData(masterKeyTemplate));

    // Create an encrypted keyset from the existing one.
    KeysetHandle handle2 = new KeysetManager.Builder()
        .setKeysetHandle(handle1)
        .setMasterKey(masterKey)
        .build()
        .getKeysetHandle();
    assertNotNull(handle2.getEncryptedKeyset());
    assertNotEquals(handle1.getKeyset().toByteString(),
        handle2.getEncryptedKeyset().getEncryptedKeyset());
    KeysetHandle handle3 = EncryptedKeysetHandle.parseFrom(
        handle2.getEncryptedKeyset(), masterKey);
    assertEquals(handle1.getKeyset(), handle2.getKeyset());
    assertEquals(handle2.getKeyset(), handle3.getKeyset());
  }

  @Test
  public void testInvalidKeyset() throws Exception {
    // Encrypt the keyset with an AeadKey.
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_GCM;
    Aead masterKey = Registry.INSTANCE.getPrimitive(
        Registry.INSTANCE.newKeyData(masterKeyTemplate));

    EncryptedKeyset encryptedKeyset = EncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(Random.randBytes(100)))
        .build();
    try {
      KeysetHandle unused = EncryptedKeysetHandle.parseFrom(encryptedKeyset, masterKey);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected.
    }

    EncryptedKeyset encryptedKeySet3 = encryptedKeyset.toBuilder()
        .clearEncryptedKeyset()
        .build();
    try {
      KeysetHandle unused = EncryptedKeysetHandle.parseFrom(encryptedKeySet3, masterKey);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }
  }

  @Test
  public void testVoidInputs() throws Exception {
    KeysetHandle unused;

    // Encrypt the keyset with an AeadKey.
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_GCM;
    Aead masterKey = Registry.INSTANCE.getPrimitive(
        Registry.INSTANCE.newKeyData(masterKeyTemplate));

    try {
      unused = EncryptedKeysetHandle.parseFrom(new ByteArrayInputStream(new byte[0]), masterKey);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = EncryptedKeysetHandle.parseFrom(new byte[0], masterKey);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = EncryptedKeysetHandle.parseFrom((ByteArrayInputStream) null, masterKey);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    // If someone feels adventurous, try encrypting empty strings and use the result as wrapped keys
  }
}
