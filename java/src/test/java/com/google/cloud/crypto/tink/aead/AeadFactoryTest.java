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

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.TestUtil;

import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for AeadFactory.
 */
@RunWith(JUnit4.class)
public class AeadFactoryTest {

  @Before
  public void setUp() throws Exception {
    AeadFactory.registerStandardKeyTypes();
  }

  @Test
  public void testMultipleKeys() throws Exception {
    String aesCtrKeyValue = "0123456789abcdef";
    String hmacKeyValue = "0123456789123456";
    int ivSize = 12;
    int tagSize = 16;

    Key primary = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK);
    Key raw = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        43,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.LEGACY);

    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);

    assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(primary));
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertEquals(
        CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length  + ivSize + tagSize,
        ciphertext.length);
  }

  @Test
  public void testRawKeyAsPrimary() throws Exception {
    String aesCtrKeyValue = "0123456789abcdef";
    String hmacKeyValue = "0123456789123456";
    int ivSize = 12;
    int tagSize = 16;

    Key primary = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key raw = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        43,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.LEGACY);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertEquals(
        CryptoFormat.RAW_PREFIX_SIZE + plaintext.length  + ivSize + tagSize,
        ciphertext.length);
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    String aesCtrKeyValue = "0123456789abcdef";
    String hmacKeyValue = "0123456789123456";
    int ivSize = 12;
    int tagSize = 16;

    Key primary = TestUtil.createKey(
        TestUtil.createAesCtrHmacAeadKey(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary));
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertEquals(
        CryptoFormat.RAW_PREFIX_SIZE + plaintext.length  + ivSize + tagSize,
        ciphertext.length);
  }
}
