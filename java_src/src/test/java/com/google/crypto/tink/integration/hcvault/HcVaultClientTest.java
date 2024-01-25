// Copyright 2023 Google LLC
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

package com.google.crypto.tink.integration.hcvault;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.KmsClientsTestUtil;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.KmsAeadKeyManager;
import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HcVaultClient. */
@RunWith(JUnit4.class)
public final class HcVaultClientTest {
  private static final String KEY_URI = "hcvault://hcvault.corp.com:8200/transit/keys/key-1";
  private static final String KEY_URI_2 = "hcvault://hcvault.corp.com:8200/transit/keys/key-2";
  private static final String INVALID_KEY = "hcvault://hcvault.corp.com:8200/transit/keys/invalid";
  private static final String TOKEN = ""; // Your token goes here

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Before
  public void setUp() {
    KmsClientsTestUtil.reset();
  }

  private static void registerWithFakeHcVault(String keyUri) throws Exception {
    KmsClients.add(HcVaultClient.create(FakeHcVault.fromURI(keyUri), keyUri));
  }

  @Test
  public void registerWithKeyUriAndFakeHcVault_kmsAeadWorks() throws Exception {
    // Register a client bound to a single key.
    registerWithFakeHcVault(KEY_URI);

    // Create a KmsAead primitive
    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(KEY_URI);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void registerWithKeyUriAndFakeHcVault_kmsEnvelopeAeadWorks() throws Exception {
    // Register a client bound to a single key.
    registerWithFakeHcVault(KEY_URI);

    // Create an envelope encryption AEAD primitive
    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    KeyTemplate envelopeTemplate =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(KEY_URI, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead kmsEnvelopeAead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsEnvelopeAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsEnvelopeAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void registerWithKeyUriAndFakeHcVault_kmsAeadCanOnlyBeCreatedForRegisteredKeyUri()
      throws Exception {
    registerWithFakeHcVault(KEY_URI);

    // getPrimitive works for keyUri
    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(KEY_URI);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead unused = handle.getPrimitive(Aead.class);

    // getPrimitive does not work for keyUri2
    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(KEY_URI_2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    assertThrows(GeneralSecurityException.class, () -> handle2.getPrimitive(Aead.class));
  }

  @Test
  public void registerBoundWithFakeHcVault_kmsEnvelopeAeadCanOnlyBeCreatedForBoundedUri()
      throws Exception {
    registerWithFakeHcVault(KEY_URI);

    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    // getPrimitive works for KEY_URI
    KeyTemplate envelopeTemplate =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(KEY_URI, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead unused = handle.getPrimitive(Aead.class);

    // getPrimitive does not work for KEY_URI_2
    KeyTemplate envelopeTemplate2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(KEY_URI_2, dekTemplate);
    KeysetHandle handle2 = KeysetHandle.generateNew(envelopeTemplate2);
    assertThrows(GeneralSecurityException.class, () -> handle2.getPrimitive(Aead.class));
  }

  @Test
  public void registerTwoBoundWithFakeHcVault_kmsAeadWorks() throws Exception {
    registerWithFakeHcVault(KEY_URI);
    registerWithFakeHcVault(KEY_URI_2);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(KEY_URI);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(KEY_URI_2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    Aead kmsAead2 = handle2.getPrimitive(Aead.class);
    byte[] ciphertext2 = kmsAead2.encrypt(plaintext, associatedData);
    byte[] decrypted2 = kmsAead2.decrypt(ciphertext2, associatedData);
    assertThat(decrypted2).isEqualTo(plaintext);
  }

  @Test
  public void registerUnboundWithFakeHcVault_kmsAeadWorks() throws Exception {
    KmsClients.add(HcVaultClient.create(FakeHcVault.fromURI(KEY_URI)));

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(KEY_URI);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead aead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void kmsAeadCannotDecryptCiphertextOfDifferentUri() throws Exception {
    registerWithFakeHcVault(KEY_URI);
    registerWithFakeHcVault(KEY_URI_2);

    KeyTemplate kmsTemplate = KmsAeadKeyManager.createKeyTemplate(KEY_URI);
    KeysetHandle handle = KeysetHandle.generateNew(kmsTemplate);
    Aead kmsAead = handle.getPrimitive(Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsAead.encrypt(plaintext, associatedData);

    KeyTemplate kmsTemplate2 = KmsAeadKeyManager.createKeyTemplate(KEY_URI_2);
    KeysetHandle handle2 = KeysetHandle.generateNew(kmsTemplate2);
    Aead kmsAead2 = handle2.getPrimitive(Aead.class);
    assertThrows(
        GeneralSecurityException.class, () -> kmsAead2.decrypt(ciphertext, associatedData));
  }

  @Test
  public void invalidUri_fails() throws Exception {
    String invalidUri = "hcvaul://@#$%&";
    FakeHcVault fakeHcVault = FakeHcVault.fromURI(invalidUri);
    assertThrows(
        IllegalArgumentException.class, () -> HcVaultClient.create(fakeHcVault, invalidUri));
  }
}
