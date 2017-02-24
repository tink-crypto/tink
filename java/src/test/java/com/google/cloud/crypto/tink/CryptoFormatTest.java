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
import static org.junit.Assert.assertTrue;

import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.PrefixType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.StatusType;

import org.junit.Test;

/**
 * Tests for CryptoFormat.
 */
public class CryptoFormatTest {
  /**
   * Tests that prefix is generated correctly.
   */
  public void testPrefix(PrefixType type, int... keyIds) throws Exception {
    for (int keyId : keyIds) {
      Key key = TestUtil.createKey(
          TestUtil.createHmacKey(),
          keyId,
          StatusType.ENABLED,
          type);
      if (type == PrefixType.RAW) {
        assertEquals(CryptoFormat.RAW_PREFIX_SIZE, CryptoFormat.getPrefix(key).length);
      } else {
        assertEquals(CryptoFormat.NON_RAW_PREFIX_SIZE, CryptoFormat.getPrefix(key).length);
      }
    }
  }

  /**
   * Tests that prefixes for keys with "extreme" key id are generated correctly.
   */
  @Test
  public void testPrefixWithWeirdKeyIds() throws Exception {
    testPrefix(PrefixType.RAW, 0, -1, 2147483647 /* INT_MAX */, -2147483648 /* INT_MIN */);
    testPrefix(PrefixType.TINK, 0, -1, 2147483647, -2147483648);
    testPrefix(PrefixType.LEGACY, 0, -1, 2147483647, -2147483648);
  }
}
