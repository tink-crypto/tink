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

import static junit.framework.Assert.fail;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.Mac;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.Random;
import com.google.protobuf.Any;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for MacFactory.
 */
@RunWith(JUnit4.class)
public class MacFactoryTest {
  private static final int HMAC_KEY_SIZE = 20;

  @Before
  public void setUp() throws Exception {
    MacFactory.registerStandardKeyTypes();
  }

  @Test
  public void testMultipleKeys() throws Exception {
    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK);
    Key raw = TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        43,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.LEGACY);
    HmacKey hmacKey = TestUtil.createHmacKey(keyValue, 16);
    Key tink = TestUtil.createKey(
        hmacKey,
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.LEGACY);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy, tink));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] tag = mac.computeMac(plaintext);
    byte[] prefix = Arrays.copyOfRange(tag, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(primary));
    assertEquals(prefix.length + 16 /* TAG */, tag.length);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      fail("Valid MAC, should not throw exception");
    }

    // mac with a non-primary key, verify with the keyset
    Mac mac2 = Registry.INSTANCE.getPrimitive(Any.pack(hmacKey));
    tag = mac2.computeMac(plaintext);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      fail("Valid MAC, should not throw exception");
    }

    // mac with a RAW key, verify with the keyset
    mac2 = Registry.INSTANCE.getPrimitive(Any.pack(TestUtil.createHmacKey(keyValue, 16)));
    tag = mac2.computeMac(plaintext);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      fail("Valid MAC, should not throw exception");
    }

    // mac with a RAW key not in the keyset, decrypt with the keyset should fail
    byte[] keyValue2 = Random.randBytes(HMAC_KEY_SIZE);
    mac2 = Registry.INSTANCE.getPrimitive(Any.pack(TestUtil.createHmacKey(keyValue2, 16)));
    tag = mac2.computeMac(plaintext);
    try {
      mac.verifyMac(tag, plaintext);
      fail("Invalid MAC MAC, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }

  @Test
  public void testRawKeyAsPrimary() throws Exception {
    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key raw = TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        43,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key legacy = TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        44,
        KeyStatusType.ENABLED,
        OutputPrefixType.LEGACY);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary, raw, legacy));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] tag = mac.computeMac(plaintext);
    // no prefix
    assertEquals(16 /* TAG */, tag.length);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      fail("Valid MAC, should not throw exception");
    }
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "blah".getBytes("UTF-8");
    byte[] tag = mac.computeMac(plaintext);
    // no prefix
    assertEquals(16 /* TAG */, tag.length);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      fail("Valid MAC, should not throw exception");
    }
  }
}
