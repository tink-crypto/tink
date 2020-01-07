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

package com.google.crypto.tink;

import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static org.junit.Assert.fail;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for NoSecretKeysetHandle. */
@RunWith(JUnit4.class)
public class NoSecretKeysetHandleTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
  }

  @Test
  public void testBasic() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'KeysetManager.withEmptyKeyset()', which
    // is not currently held
    KeysetManager manager = KeysetManager.withEmptyKeyset().rotate(template);
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
    Keyset keyset = manager.getKeysetHandle().getKeyset();
    try {
      KeysetHandle unused = NoSecretKeysetHandle.parseFrom(keyset.toByteArray());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains secret key material");
    }
  }

  @Test
  public void testVoidInputs() throws Exception {
    KeysetHandle unused;

    try {
      unused = NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(new byte[0]));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = NoSecretKeysetHandle.read(BinaryKeysetReader.withBytes(new byte[0]));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }
  }
}
