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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.integration.CloudKmsClient;
import com.google.crypto.tink.integration.GcpKmsClient;
import com.google.crypto.tink.subtle.KmsClient;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for KmsAeadKeyManager.
 */
@RunWith(JUnit4.class)
public class KmsAeadKeyManagerTest {
  private KmsClient kmsClient;

  @Before
  public void setUp() throws Exception {
    kmsClient = new CloudKmsClient()
        .withGcpKmsClient(GcpKmsClient.fromServiceAccount(
            TestUtil.SERVICE_ACCOUNT_FILE));
  }

  @Test
  public void testGcpKmsKeyRestricted_WithRegistry() throws Exception {
    Registry.INSTANCE.registerKeyManager(
        KmsAeadKeyManager.TYPE_URL,
        new KmsAeadKeyManager(kmsClient));
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.createKmsAeadKeyTemplate(TestUtil.RESTRICTED_CRYPTO_KEY_URI));
    TestUtil.runBasicAeadFactoryTests(keysetHandle);
  }

  @Test
  public void testGcpKmsKeyRestricted_WithCustomKeyManager() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.createKmsAeadKeyTemplate(TestUtil.RESTRICTED_CRYPTO_KEY_URI));
    KmsAeadKeyManager customKeyManager = new KmsAeadKeyManager(kmsClient);
    TestUtil.runBasicAeadFactoryTests(keysetHandle, customKeyManager);
  }
}
