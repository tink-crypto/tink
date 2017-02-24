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

package com.google.cloud.crypto.tink.mac;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.Mac;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.PrefixType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.StatusType;
import com.google.cloud.crypto.tink.TestUtil;

import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for MacFactory.
 */
public class MacFactoryTest {

  @Before
  public void setUp() throws Exception {
    MacFactory.registerStandardKeyTypes();
  }

  @Test
  public void testMultipleKeys() throws Exception {
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKey(),
        42,
        StatusType.ENABLED,
        PrefixType.TINK);
    Key raw = TestUtil.createKey(
        TestUtil.createHmacKey(),
        43,
        StatusType.ENABLED,
        PrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createHmacKey(),
        44,
        StatusType.ENABLED,
        PrefixType.LEGACY);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] tag = mac.computeMac(plaintext);
    byte[] prefix = Arrays.copyOfRange(tag, 0, 5);
    assertArrayEquals(prefix, CryptoFormat.getPrefix(primary));
    assertEquals(prefix.length + 16 /* TAG */, tag.length);
    assertTrue(mac.verifyMac(tag, plaintext));
  }

  @Test
  public void testRawKeyAsPrimary() throws Exception {
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKey(),
        42,
        StatusType.ENABLED,
        PrefixType.RAW);
    Key raw = TestUtil.createKey(
        TestUtil.createHmacKey(),
        43,
        StatusType.ENABLED,
        PrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createHmacKey(),
        44,
        StatusType.ENABLED,
        PrefixType.LEGACY);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] tag = mac.computeMac(plaintext);
    // no prefix
    assertEquals(16 /* TAG */, tag.length);
    assertTrue(mac.verifyMac(tag, plaintext));
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKey(),
        42,
        StatusType.ENABLED,
        PrefixType.RAW);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "blah".getBytes("UTF-8");
    byte[] tag = mac.computeMac(plaintext);
    // no prefix
    assertEquals(16 /* TAG */, tag.length);
    assertTrue(mac.verifyMac(tag, plaintext));
  }
}
