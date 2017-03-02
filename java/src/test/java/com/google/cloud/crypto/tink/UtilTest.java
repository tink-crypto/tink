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

package com.google.cloud.crypto.tink;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.protobuf.TextFormat;
import java.security.GeneralSecurityException;
import org.junit.Test;

/**
 * Tests for Util.
 */
public class UtilTest {
  /**
   * Tests that getKeysetInfo doesn't contain key material.
   */
  @Test
  public void testGetKeysetInfo() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =  TestUtil.createKeyset(TestUtil.createKey(
        TestUtil.createHmacKey(keyValue, 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK));
    assertTrue(TextFormat.printToUnicodeString(keyset).contains(keyValue));

    KeysetInfo keysetInfo = Util.getKeysetInfo(keyset);
    assertFalse(TextFormat.printToUnicodeString(keysetInfo).contains(keyValue));
  }
}
