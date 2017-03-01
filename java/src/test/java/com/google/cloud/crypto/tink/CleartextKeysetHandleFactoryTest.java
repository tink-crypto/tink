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
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.protobuf.TextFormat;
import java.security.GeneralSecurityException;
import org.junit.Test;

/**
 * Tests for CleartextKeysetHandleFactory.
 */
public class CleartextKeysetHandleFactoryTest {
  @Test
  public void testBasic() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset1 =  TestUtil.createKeyset(TestUtil.createKey(
        TestUtil.createHmacKey(keyValue),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK));
    KeysetHandle handle1 = CleartextKeysetHandleFactory.fromBinaryFormat(keyset1.toByteArray());
    assertEquals(keyset1, handle1.getKeyset());

    KeysetHandle handle2 = CleartextKeysetHandleFactory.fromTextFormat(
        TextFormat.printToUnicodeString(keyset1));
    assertEquals(keyset1, handle2.getKeyset());
  }

  @Test
  public void testInvalidKeyset() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =  TestUtil.createKeyset(TestUtil.createKey(
        TestUtil.createHmacKey(keyValue),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK));
    byte[] proto = keyset.toByteArray();
    proto[0] = (byte) ~proto[0];
    try {
      KeysetHandle handle = CleartextKeysetHandleFactory.fromBinaryFormat(proto);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("invalid keyset"));
    }

    String str = TextFormat.printToUnicodeString(keyset);
    try {
      KeysetHandle handle = CleartextKeysetHandleFactory.fromTextFormat(str + "invalid");
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("invalid keyset"));
    }
  }
}
