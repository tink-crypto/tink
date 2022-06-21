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

package com.google.crypto.tink.mac;

import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for MacFactory.
 */
@RunWith(JUnit4.class)
public class MacFactoryTest {
  private static final int HMAC_KEY_SIZE = 20;

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    DeterministicAeadConfig.register(); // need this for testInvalidKeyMaterial.
  }

  @Test
  public void testMultipleKeys() throws Exception {
    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    Key tink = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          42,
          KeyStatusType.ENABLED,
          OutputPrefixType.TINK);
    Key legacy = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          43,
          KeyStatusType.ENABLED,
          OutputPrefixType.LEGACY);
    Key raw = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          44,
          KeyStatusType.ENABLED,
          OutputPrefixType.RAW);
    Key crunchy = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          45,
          KeyStatusType.ENABLED,
          OutputPrefixType.CRUNCHY);
    Key[] keys = new Key[] {tink, legacy, raw, crunchy};
    int j = keys.length;
    for (int i = 0; i < j; i++) {
      KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            keys[i],
            keys[(i + 1) % j],
            keys[(i + 2) % j],
            keys[(i + 3) % j]));
      Mac mac = MacFactory.getPrimitive(keysetHandle);
      byte[] plaintext = "plaintext".getBytes(UTF_8);
      byte[] tag = mac.computeMac(plaintext);
      if (!keys[i].getOutputPrefixType().equals(OutputPrefixType.RAW)) {
        byte[] prefix = Arrays.copyOf(tag, CryptoFormat.NON_RAW_PREFIX_SIZE);
        assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(keys[i]));
      }
      try {
        mac.verifyMac(tag, plaintext);
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid MAC, should not throw exception: " + i, e);
      }

      // Modify plaintext or tag and make sure the verifyMac failed.
      byte[] plaintextAndTag = Bytes.concat(plaintext, tag);
      for (int b = 0; b < plaintextAndTag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modified = Arrays.copyOf(plaintextAndTag, plaintextAndTag.length);
          modified[b] ^= (byte) (1 << bit);
          assertThrows(
              GeneralSecurityException.class,
              () ->
                  mac.verifyMac(
                      Arrays.copyOfRange(modified, plaintext.length, modified.length),
                      Arrays.copyOf(modified, plaintext.length)));
        }
      }

      // mac with a non-primary RAW key, verify with the keyset
      KeysetHandle keysetHandle2 = TestUtil.createKeysetHandle(
          TestUtil.createKeyset(raw, legacy, tink, crunchy));
      Mac mac2 = MacFactory.getPrimitive(keysetHandle2);
      tag = mac2.computeMac(plaintext);
      try {
        mac.verifyMac(tag, plaintext);
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid MAC, should not throw exception", e);
      }

      // mac with a random key not in the keyset, verify with the keyset should fail
      byte[] keyValue2 = Random.randBytes(HMAC_KEY_SIZE);
      Key random = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue2, 16),
          44,
          KeyStatusType.ENABLED,
          OutputPrefixType.TINK);
      keysetHandle2 = TestUtil.createKeysetHandle(
          TestUtil.createKeyset(random));
      mac2 = MacFactory.getPrimitive(keysetHandle2);
      final byte[] tag2 = mac2.computeMac(plaintext);
      assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag2, plaintext));
    }
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKeyData(keyValue, 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primary));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "blah".getBytes(UTF_8);
    byte[] tag = mac.computeMac(plaintext);
    // no prefix
    assertEquals(16 /* TAG */, tag.length);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Valid MAC, should not throw exception", e);
    }
  }

  @Test
  public void testInvalidKeyMaterial() throws Exception {
    Key valid =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(Random.randBytes(HMAC_KEY_SIZE), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Key invalid =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(64), 43, KeyStatusType.ENABLED, OutputPrefixType.TINK);

    final KeysetHandle keysetHandle =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(valid, invalid));
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> MacFactory.getPrimitive(keysetHandle));
    assertExceptionContains(e, "com.google.crypto.tink.Mac not supported");

    // invalid as the primary key.
    final KeysetHandle keysetHandle2 =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(invalid, valid));
    e = assertThrows(GeneralSecurityException.class, () -> MacFactory.getPrimitive(keysetHandle2));
    assertExceptionContains(e, "com.google.crypto.tink.Mac not supported");
  }
}
