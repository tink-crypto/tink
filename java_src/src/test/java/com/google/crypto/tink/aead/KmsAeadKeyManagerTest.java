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
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.FakeKmsClient;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ExtensionRegistryLite;
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
  public void testKmsAeadWithBoundedClient_success() throws Exception {
    String keyUri = FakeKmsClient.createFakeKeyUri();
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(AeadKeyTemplates.createKmsAeadKeyTemplate(keyUri));
    TestUtil.runBasicAeadTests(keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void createKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    String keyUri = "some example KEK URI";
    KeyTemplate template = KmsAeadKeyManager.createKeyTemplate(keyUri);
    assertThat(new KmsAeadKeyManager().getKeyType()).isEqualTo(template.getTypeUrl());
    assertThat(KeyTemplate.OutputPrefixType.RAW).isEqualTo(template.getOutputPrefixType());

    KmsAeadKeyFormat format =
        KmsAeadKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(keyUri).isEqualTo(format.getKeyUri());
  }

  @Test
  public void createKeyTemplate_multipleKeysWithSameKek() throws Exception {
    String keyUri = FakeKmsClient.createFakeKeyUri();

    KeyTemplate template1 = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle1 = KeysetHandle.generateNew(template1);
    Aead aead1 = handle1.getPrimitive(Aead.class);

    KeyTemplate template2 = KmsAeadKeyManager.createKeyTemplate(keyUri);
    KeysetHandle handle2 = KeysetHandle.generateNew(template2);
    Aead aead2 = handle2.getPrimitive(Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    assertThat(aead1.decrypt(aead2.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }
}
