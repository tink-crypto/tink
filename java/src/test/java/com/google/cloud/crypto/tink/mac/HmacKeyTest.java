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
import static org.junit.Assert.assertEquals;

import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.Mac;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for HmacKey.
 */
@RunWith(JUnit4.class)
public class HmacKeyTest {
  private static final int HMAC_KEY_SIZE = 20;

  @Before
  public void setUp() throws Exception {
    MacFactory.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKey(keyValue, 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)));
    Mac mac = MacFactory.getPrimitive(keysetHandle);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] tag = mac.computeMac(plaintext);
    assertEquals(16 + CryptoFormat.NON_RAW_PREFIX_SIZE, tag.length);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      fail("Valid MAC, should not throw exception");
    }

    byte original = plaintext[0];
    plaintext[0] = (byte) ~original;
    try {
      mac.verifyMac(tag, plaintext);
      fail("Invalid MAC, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }

    plaintext[0] = original;
    original = tag[0];
    tag[0] = (byte) ~original;
    try {
      mac.verifyMac(tag, plaintext);
      fail("Invalid MAC, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }

    tag[0] = original;
    original = tag[CryptoFormat.NON_RAW_PREFIX_SIZE];
    tag[CryptoFormat.NON_RAW_PREFIX_SIZE] = (byte) ~original;
    try {
      mac.verifyMac(tag, plaintext);
      fail("Invalid MAC, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }
}
