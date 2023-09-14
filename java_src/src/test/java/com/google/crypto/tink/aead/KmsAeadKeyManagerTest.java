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

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.testing.FakeKmsClient;
import com.google.crypto.tink.testing.TestUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KmsAeadKeyManager. */
@RunWith(JUnit4.class)
public class KmsAeadKeyManagerTest {
  @Before
  public void setUp() throws Exception {
    KmsClients.add(new FakeKmsClient());
    AeadConfig.register();
  }

  @Test
  public void testKmsAead_success() throws Exception {
    String keyUri = FakeKmsClient.createFakeKeyUri();
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(KmsAeadKeyManager.createKeyTemplate(keyUri));
    TestUtil.runBasicAeadTests(keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void createKeyTemplate() throws Exception {
    String keyUri = "some example KEK URI";
    assertThat(KmsAeadKeyManager.createKeyTemplate(keyUri).toParameters())
        .isEqualTo(LegacyKmsAeadParameters.create(keyUri));
  }
}
