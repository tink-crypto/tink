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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for DeterministicAeadFactory. */
@RunWith(JUnit4.class)
public class DeterministicAeadFactoryTest {
  private Integer[] keySizeInBytes;

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register(); // need this for testInvalidKeyMaterial.
    DeterministicAeadConfig.register();
  }

  @Before
  public void setUp2() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip all DeterministicAeadFactory tests");
      keySizeInBytes = new Integer[] {};
    } else {
      keySizeInBytes = new Integer[] {64};
    }
  }

  @Test
  public void testEncrytDecrypt() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(DeterministicAeadKeyTemplates.AES256_SIV);
    DeterministicAead aead = DeterministicAeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = aead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = aead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = aead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);
  }

  @Test
  public void testMultipleKeys() throws Exception {
    for (int keySize : keySizeInBytes) {
      testMultipleKeys(keySize);
    }
  }

  private static void testMultipleKeys(int keySize) throws Exception {
    Key primary =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Key raw =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 43, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    Key legacy =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);
    Key tink =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            45,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    KeysetHandle keysetHandle =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(primary, raw, legacy, tink));

    DeterministicAead daead = DeterministicAeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(primary));
    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));
    assertEquals(CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length + 16, ciphertext.length);

    // encrypt with a non-primary RAW key and decrypt with the keyset
    KeysetHandle keysetHandle2 =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(raw, legacy, tink));
    DeterministicAead daead2 = DeterministicAeadFactory.getPrimitive(keysetHandle2);
    ciphertext = daead2.encryptDeterministically(plaintext, associatedData);
    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));

    // encrypt with a random key not in the keyset, decrypt with the keyset should fail
    Key random =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    keysetHandle2 = TestUtil.createKeysetHandle(TestUtil.createKeyset(random));
    daead2 = DeterministicAeadFactory.getPrimitive(keysetHandle2);
    ciphertext = daead2.encryptDeterministically(plaintext, associatedData);
    try {
      daead.decryptDeterministically(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }
  }

  @Test
  public void testRawKeyAsPrimary() throws Exception {
    for (int keySize : keySizeInBytes) {
      testRawKeyAsPrimary(keySize);
    }
  }

  private static void testRawKeyAsPrimary(int keySize) throws Exception {
    Key primary =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 42, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    Key raw =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 43, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    Key legacy =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);
    KeysetHandle keysetHandle =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(primary, raw, legacy));

    DeterministicAead daead = DeterministicAeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);

    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));
    assertEquals(CryptoFormat.RAW_PREFIX_SIZE + plaintext.length + 16, ciphertext.length);
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    for (int keySize : keySizeInBytes) {
      testSmallPlaintextWithRawKey(keySize);
    }
  }

  private static void testSmallPlaintextWithRawKey(int keySize) throws Exception {
    Key primary =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 42, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(TestUtil.createKeyset(primary));

    DeterministicAead daead = DeterministicAeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = Random.randBytes(1);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);

    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));
    assertEquals(CryptoFormat.RAW_PREFIX_SIZE + plaintext.length + 16, ciphertext.length);
  }

  @Test
  public void testInvalidKeyMaterial() throws Exception {
    Key valid =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(64), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK);
    Key invalid =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(
                Random.randBytes(16), 12, Random.randBytes(16), 16),
            43,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);

    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(TestUtil.createKeyset(valid, invalid));
    try {
      DeterministicAeadFactory.getPrimitive(keysetHandle);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(
          e, "not match requested primitive type com.google.crypto.tink.DeterministicAead");
    }

    // invalid as the primary key.
    keysetHandle = TestUtil.createKeysetHandle(TestUtil.createKeyset(invalid, valid));
    try {
      DeterministicAeadFactory.getPrimitive(keysetHandle);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(
          e, "not match requested primitive type com.google.crypto.tink.DeterministicAead");
    }
  }
}
