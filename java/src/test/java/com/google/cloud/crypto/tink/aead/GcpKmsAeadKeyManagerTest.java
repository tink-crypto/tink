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

package com.google.cloud.crypto.tink.aead;

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.ServiceAccountGcpCredentialFactory;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for GcpKmsAead and its key manager.
 */
@RunWith(JUnit4.class)
public class GcpKmsAeadKeyManagerTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    Registry.INSTANCE.registerKeyManager(
        "type.googleapis.com/google.cloud.crypto.tink.GcpKmsAeadKey",
        new GcpKmsAeadKeyManager(new ServiceAccountGcpCredentialFactory(
            TestUtil.SERVICE_ACCOUNT_FILE)));
  }

  @Test
  public void testGcpKmsKeyRestricted() throws Exception {
    KeysetHandle keysetHandle = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(
            TestUtil.createKey(
                // This key is restricted to {@code TestUtil.SERVICE_ACCOUNT_FILE}.
                TestUtil.createGcpKmsAeadKeyData(TestUtil.RESTRICTED_CRYPTO_KEY_URI),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)));

    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    TestUtil.runBasicTests(aead);

    // Now with {@code GcpKmsAeadKeyManager} as a custom key manager.
    GcpKmsAeadKeyManager customKeyManager =
        new GcpKmsAeadKeyManager(new ServiceAccountGcpCredentialFactory(
            TestUtil.SERVICE_ACCOUNT_FILE));
    aead = AeadFactory.getPrimitive(keysetHandle, customKeyManager);
    TestUtil.runBasicTests(aead);
  }
}
