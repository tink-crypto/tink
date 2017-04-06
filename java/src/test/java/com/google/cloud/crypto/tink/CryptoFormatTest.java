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

import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for CryptoFormat.
 */
@RunWith(JUnit4.class)
public class CryptoFormatTest {
  /**
   * Tests that prefix is generated correctly.
   */
  public void testPrefix(OutputPrefixType type, int... keyIds) throws Exception {
    String keyValue = "01234567890123456";
    for (int keyId : keyIds) {
      Key key = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
          keyId,
          KeyStatusType.ENABLED,
          type);
      if (type == OutputPrefixType.RAW) {
        assertEquals(CryptoFormat.RAW_PREFIX_SIZE, CryptoFormat.getOutputPrefix(key).length);
      } else {
        assertEquals(CryptoFormat.NON_RAW_PREFIX_SIZE, CryptoFormat.getOutputPrefix(key).length);
      }
    }
  }

  /**
   * Tests that prefixes for keys with "extreme" key id are generated correctly.
   */
  @Test
  public void testPrefixWithWeirdKeyIds() throws Exception {
    testPrefix(OutputPrefixType.RAW, 0, -1, 2147483647 /* INT_MAX */, -2147483648 /* INT_MIN */);
    testPrefix(OutputPrefixType.TINK, 0, -1, 2147483647, -2147483648);
    testPrefix(OutputPrefixType.LEGACY, 0, -1, 2147483647, -2147483648);
  }
}
