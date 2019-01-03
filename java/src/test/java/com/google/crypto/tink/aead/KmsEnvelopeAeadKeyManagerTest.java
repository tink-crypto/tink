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
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Random;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code KmsEnvelopeAead} and {@code KmsEnvelopeAeadKeyManager}.
 */
@RunWith(JUnit4.class)
public class KmsEnvelopeAeadKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    KmsClients.add(new GcpKmsClient()
        .withCredentials(TestUtil.SERVICE_ACCOUNT_FILE));
    AeadConfig.register();
  }

  @Test
  public void testGcpKmsKeyRestricted() throws Exception {
    KeyTemplate dekTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
            TestUtil.RESTRICTED_CRYPTO_KEY_URI, dekTemplate));
    TestUtil.runBasicAeadTests(keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void testParsingInvalidCiphertexts() throws Exception {
    KeyTemplate dekTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(
            TestUtil.RESTRICTED_CRYPTO_KEY_URI, dekTemplate));

    Aead aead = keysetHandle.getPrimitive(Aead.class);
    byte[] plaintext = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
    // Skip Tink's header.
    byte[] header = new byte[CryptoFormat.NON_RAW_PREFIX_SIZE];
    buffer.get(header, 0, header.length);
    int encryptedDekSize = buffer.getInt();
    byte[] encryptedDek = new byte[encryptedDekSize];
    buffer.get(encryptedDek, 0, encryptedDekSize);
    byte[] payload = new byte[buffer.remaining()];
    buffer.get(payload, 0, buffer.remaining());

    // valid, should work
    byte[] ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .put(header)
        .putInt(encryptedDekSize)
        .put(encryptedDek)
        .put(payload)
        .array();
    assertArrayEquals(plaintext, aead.decrypt(ciphertext2, aad));

    // negative length
    ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .put(header)
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
        .put(header)
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
        .put(header)
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
