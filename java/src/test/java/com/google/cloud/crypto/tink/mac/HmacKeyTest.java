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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.Mac;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.mac.MacFactory;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests for HmacKey.
 */
public class HmacKeyTest {

  @Before
  public void setUp() throws Exception {
    MacFactory.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    String keyValue = "01234567890123456";
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
    assertTrue(mac.verifyMac(tag, plaintext));

    byte original = plaintext[0];
    plaintext[0] = (byte) ~original;
    assertFalse(mac.verifyMac(tag, plaintext));

    plaintext[0] = original;
    original = tag[0];
    tag[0] = (byte) ~original;
    assertFalse(mac.verifyMac(tag, plaintext));

    tag[0] = original;
    original = tag[CryptoFormat.NON_RAW_PREFIX_SIZE];
    tag[CryptoFormat.NON_RAW_PREFIX_SIZE] = (byte) ~original;
    assertFalse(mac.verifyMac(tag, plaintext));
  }
}
