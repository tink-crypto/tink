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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for NoSecretKeysetHandle.
 */
@RunWith(JUnit4.class)
public class NoSecretKeysetHandleTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();
    assertNull(manager.getKeysetHandle().getEncryptedKeyset());
    Keyset keyset = manager.getKeysetHandle().getKeyset();
    try {
      KeysetHandle unused = NoSecretKeysetHandle.parseFrom(keyset.toByteArray());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains secret key material");
    }

    // This is a REMOTE key.
    KeyTemplate template2 = TestUtil.createKmsEnvelopeAeadKeyTemplate(
        KeyData.newBuilder().build(), KeyTemplate.newBuilder().build());
    KeysetManager manager2 = new KeysetManager.Builder()
        .setKeyTemplate(template2)
        .build()
        .rotate();
    Keyset keyset2 = manager2.getKeysetHandle().getKeyset();
    try {
      KeysetHandle unused = NoSecretKeysetHandle.parseFrom(keyset2.toByteArray());
    } catch (GeneralSecurityException e) {
      fail("Should be allowed to load non secret keyset");
    }
  }

  @Test
  public void testVoidInputs() throws Exception {
    KeysetHandle unused;

    try {
      unused = NoSecretKeysetHandle.parseFrom(new ByteArrayInputStream(new byte[0]));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = NoSecretKeysetHandle.parseFrom(new byte[0]);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = NoSecretKeysetHandle.parseFrom((ByteArrayInputStream) null);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }
  }
}
