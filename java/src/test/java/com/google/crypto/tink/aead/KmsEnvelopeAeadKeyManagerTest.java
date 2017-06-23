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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.EnvelopeTestUtil;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.ServiceAccountGcpCredentialFactory;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code KmsEnvelopeAead} and {@code KmsEnvelopeAeadKeyManager}.
 */
@RunWith(JUnit4.class)
public class KmsEnvelopeAeadKeyManagerTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes();
    Registry.INSTANCE.registerKeyManager(
        GcpKmsAeadKeyManager.TYPE_URL,
        new GcpKmsAeadKeyManager(new ServiceAccountGcpCredentialFactory(
            TestUtil.SERVICE_ACCOUNT_FILE)));
  }

  @Test
  public void testGcpKmsKeyRestricted() throws Exception {
    KeyTemplate dekTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    // This key is restricted to {@code TestUtil.SERVICE_ACCOUNT_FILE}.
    KeyData kmsKey = EnvelopeTestUtil.createGcpKmsAeadKeyData(
        TestUtil.RESTRICTED_CRYPTO_KEY_URI);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createKmsEnvelopeAeadKeyData(kmsKey, dekTemplate),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)));
    TestUtil.runBasicAeadFactoryTests(keysetHandle);

    // Now with {@code GcpKmsAeadKeyManager} as a custom key manager.
    GcpKmsAeadKeyManager customKeyManager =
        new GcpKmsAeadKeyManager(new ServiceAccountGcpCredentialFactory(
            TestUtil.SERVICE_ACCOUNT_FILE));
    TestUtil.runBasicAeadFactoryTests(keysetHandle, customKeyManager);
  }

  @Test
  public void testParsingInvalidCiphertexts() throws Exception {
    KeyTemplate dekTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeyData kmsKey = EnvelopeTestUtil.createGcpKmsAeadKeyData(
        TestUtil.RESTRICTED_CRYPTO_KEY_URI);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createKmsEnvelopeAeadKeyData(kmsKey, dekTemplate),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.RAW)));

    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
    int encryptedDekSize = buffer.getInt();
    byte[] encryptedDek = new byte[encryptedDekSize];
    buffer.get(encryptedDek, 0, encryptedDekSize);
    byte[] payload = new byte[buffer.remaining()];
    buffer.get(payload, 0, buffer.remaining());

    // valid, should work
    byte[] ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .putInt(encryptedDekSize)
        .put(encryptedDek)
        .put(payload)
        .array();
    assertArrayEquals(plaintext, aead.decrypt(ciphertext2, aad));

    // negative length
    ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .putInt(-1)
        .put(encryptedDek)
        .put(payload)
        .array();
    try {
      aead.decrypt(ciphertext2, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }

    // length larger than actual value
    ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .putInt(encryptedDek.length + 1)
        .put(encryptedDek)
        .put(payload)
        .array();
    try {
      aead.decrypt(ciphertext2, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }

    // length larger than total ciphertext length
    ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .putInt(encryptedDek.length + payload.length + 1)
        .put(encryptedDek)
        .put(payload)
        .array();
    try {
      aead.decrypt(ciphertext2, aad);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }
  }
}
