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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.testing.TestUtil;
import java.util.Optional;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KmsAeadKeyManager using {@code GcpKmsClient}. */
@RunWith(JUnit4.class)
public class KmsAeadKeyManagerWithGcpTest {
  @Before
  public void setUp() throws Exception {
    GcpKmsClient.register(Optional.empty(), Optional.of(TestUtil.SERVICE_ACCOUNT_FILE));
    AeadConfig.register();
  }

  // TODO(b/154273145): re-enable this.
  @Ignore
  @Test
  public void testGcpKmsKeyRestricted() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(
            AeadKeyTemplates.createKmsAeadKeyTemplate(TestUtil.RESTRICTED_CRYPTO_KEY_URI));
    TestUtil.runBasicAeadTests(keysetHandle.getPrimitive(Aead.class));
  }
}
