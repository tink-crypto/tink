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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.FakeKmsClient;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
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
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.KmsAeadKey", Aead.class))
        .isNotNull();
  }

  @Test
  public void testKmsAead_success() throws Exception {
    String keyUri = FakeKmsClient.createFakeKeyUri();
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(KmsAeadKeyManager.createKeyTemplate(keyUri));
    TestUtil.runBasicAeadTests(keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void createAeadFromLegacyKmsAeadKey_works() throws Exception {
    LegacyKmsAeadParameters parameters =
        LegacyKmsAeadParameters.create(FakeKmsClient.createFakeKeyUri());
    LegacyKmsAeadKey key = LegacyKmsAeadKey.create(parameters);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    TestUtil.runBasicAeadTests(keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void createAeadInvalidUri_throws() throws Exception {
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create("wrong uri");
    LegacyKmsAeadKey key = LegacyKmsAeadKey.create(parameters);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void createKeyTemplateGenerateNewGetPrimitive_isSameAs_clientGetAead()
      throws Exception {
    String keyUri = FakeKmsClient.createFakeKeyUri();

    // Create Aead primitive using createKeyTemplate, generateNew, and getPrimitive.
    // This requires that a KmsClient that supports keyUri is registered.
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(KmsAeadKeyManager.createKeyTemplate(keyUri));
    Aead aead1 = keysetHandle.getPrimitive(Aead.class);

    // Create Aead using FakeKmsClient.getAead.
    // No KmsClient needs to be registered.
    Aead aead2 = new FakeKmsClient().getAead(keyUri);

    // Test that aead1 and aead2 are the same.
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead1.encrypt(plaintext, associatedData);
    byte[] decrypted = aead2.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void createKeyTemplate() throws Exception {
    String keyUri = "some example KEK URI";
    assertThat(KmsAeadKeyManager.createKeyTemplate(keyUri).toParameters())
        .isEqualTo(LegacyKmsAeadParameters.create(keyUri));
  }

  @Test
  public void generateNewFromParams_works() throws Exception {
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create("some example KEK URI");
    KeysetHandle keysetHandle1 = KeysetHandle.generateNew(parameters);
    KeysetHandle keysetHandle2 = KeysetHandle.generateNew(parameters);
    // For LegacyKmsAeadParameters we expect both keysets to be the same -- however, the ID of the
    // keys may differ.
    assertThat(keysetHandle1.getAt(0).getKey().equalsKey(keysetHandle2.getAt(0).getKey())).isTrue();
  }

  @Test
  public void serializeAndParse_works() throws Exception {
    LegacyKmsAeadParameters parameters = LegacyKmsAeadParameters.create("some example KEK URI");
    KeysetHandle keysetHandle1 = KeysetHandle.generateNew(parameters);
    byte[] serialized = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(keysetHandle1);
    KeysetHandle keysetHandle2 = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serialized);
    assertThat(keysetHandle1.equalsKeyset(keysetHandle2)).isTrue();
  }
}
