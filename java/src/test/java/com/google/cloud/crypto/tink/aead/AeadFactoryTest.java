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

package com.google.cloud.crypto.tink.aead;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for AeadFactory.
 */
@RunWith(JUnit4.class)
public class AeadFactoryTest {
  private static final int AES_KEY_SIZE = 16;
  private static final int HMAC_KEY_SIZE = 20;

  @Before
  public void setUp() throws Exception {
    AeadFactory.registerStandardKeyTypes();
  }

  @Test
  public void testBasicAesCtrHmacAead() throws Exception {
    AeadFactory.registerStandardKeyTypes();
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    TestUtil.runBasicTests(aead);
  }

  @Test
  public void testMultipleKeys() throws Exception {
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key primary = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK);
    Key raw = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        43,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.LEGACY);

    Key tink = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        45,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK);

    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy, tink));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);

    assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(primary));
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length  + ivSize + tagSize,
        ciphertext.length);

    // encrypt with a non-primary RAW key and decrypt with the keyset
    KeysetHandle keysetHandle2 = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(raw, legacy, tink));
    Aead aead2 = AeadFactory.getPrimitive(keysetHandle2);
    ciphertext = aead2.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));

    // encrypt with a random key not in the keyset, decrypt with the keyset should fail
    byte[] aesCtrKeyValue2 = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue2 = Random.randBytes(HMAC_KEY_SIZE);
    Key random = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue2, ivSize, hmacKeyValue2, tagSize),
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK);
    keysetHandle2 = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(random));
    aead2 = AeadFactory.getPrimitive(keysetHandle2);
    ciphertext = aead2.encrypt(plaintext, associatedData);
    try {
      aead.decrypt(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("decryption failed"));
    }
  }

  @Test
  public void testRawKeyAsPrimary() throws Exception {
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key primary = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key raw = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        43,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.LEGACY);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertEquals(
        CryptoFormat.RAW_PREFIX_SIZE + plaintext.length  + ivSize + tagSize,
        ciphertext.length);
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key primary = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(1);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertEquals(
        CryptoFormat.RAW_PREFIX_SIZE + plaintext.length  + ivSize + tagSize,
        ciphertext.length);
  }

  /**
   * A very basic test for asynchronous encryption.
   */
  @Test
  public void testAsync() throws Exception {
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key primary = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK);

    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.asyncEncrypt(plaintext, associatedData).get();
    byte[] decrypted = aead.asyncDecrypt(ciphertext, associatedData).get();
    assertArrayEquals(plaintext, decrypted);
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] truncated = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = aead.asyncDecrypt(truncated, associatedData).get();
        fail("Decrypting a truncated ciphertext should fail");
      } catch (ExecutionException ex) {
        // The decryption should fail because the ciphertext has been truncated.
        assertTrue(ex.getCause() instanceof GeneralSecurityException);
      }
    }
  }
}
