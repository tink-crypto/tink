// Copyright 2021 Google LLC
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
import static java.util.Arrays.asList;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.KmsClientsTestUtil;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.KmsAeadKeyManager;
import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HcVaultClient. Requires a real Hashicorp Vault server and token */
@RunWith(JUnit4.class)
public final class HcVaultIntegrationTest {
  private static final String KEY_URI = "hcvault://10.10.18.215:8200/transit/keys/key-1";
  private static final String KEY_URI_2 = "hcvault://10.10.18.215:8200/transit/keys/key-2";
  private static final String INVALID_KEY = "hcvault://10.10.18.215:8200/transit/keys/invalid";
  private static final String TOKEN = "hvs.LPUqFLiJZXO3Q8kNtCawP33i"; // Your token goes here

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Before
  public void setUp() {
    KmsClientsTestUtil.reset();
  }

  @Test
  public void registerWithKeyUriAndCredentials_success() throws Exception {
    // Register a client bound to a single key.
    HcVaultClient.register(KEY_URI, TOKEN);

    KmsClient client = KmsClients.get(KEY_URI);
    assertThat(client.doesSupport(KEY_URI)).isTrue();

    String modifiedKeyUri = KEY_URI.replace("hcvault", "invalid");
    assertThat(client.doesSupport(modifiedKeyUri)).isFalse();
  }

  @Test
  public void registerWithCredentialsAndBadKeyUri_fail() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> HcVaultClient.register("blah", TOKEN));
  }

  @Test
  public void registerWithKeyUriAndHcVault_kmsAeadWorks() throws Exception {
    // Register a client bound to a single key.
    HcVaultClient.register(KEY_URI, TOKEN, false, false, Optional.empty());

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
  public void registerWithKeyUriAndHcVault_kmsEnvelopeAeadWorks() throws Exception {
    // Register a client bound to a single key.
    HcVaultClient.register(KEY_URI, TOKEN, false, false, Optional.empty());

    // Create an envelope encryption AEAD primitive
    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    KeyTemplate envelopeTemplate = KmsEnvelopeAeadKeyManager.createKeyTemplate(KEY_URI, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead kmsEnvelopeAead = handle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = kmsEnvelopeAead.encrypt(plaintext, associatedData);
    byte[] decrypted = kmsEnvelopeAead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void registerWithKeyUriAndHcVault_kmsAeadCanOnlyBeCreatedForRegisteredKeyUri()
      throws Exception {
    HcVaultClient.register(KEY_URI, TOKEN, false, false, Optional.empty());

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
  public void registerBoundWithHcVault_kmsEnvelopeAeadCanOnlyBeCreatedForBoundedUri()
      throws Exception {
    HcVaultClient.register(KEY_URI, TOKEN, false, false, Optional.empty());

    KeyTemplate dekTemplate = KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW");
    // getPrimitive works for KEY_URI
    KeyTemplate envelopeTemplate = KmsEnvelopeAeadKeyManager.createKeyTemplate(KEY_URI, dekTemplate);
    KeysetHandle handle = KeysetHandle.generateNew(envelopeTemplate);
    Aead unused = handle.getPrimitive(Aead.class);

    // getPrimitive does not work for KEY_URI_2
    KeyTemplate envelopeTemplate2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(KEY_URI_2, dekTemplate);
    KeysetHandle handle2 = KeysetHandle.generateNew(envelopeTemplate2);
    assertThrows(GeneralSecurityException.class, () -> handle2.getPrimitive(Aead.class));
  }

  @Test
  public void registerTwoBoundWithHcVault_kmsAeadWorks() throws Exception {
    HcVaultClient.register(KEY_URI, TOKEN, false, false, Optional.empty());
    HcVaultClient.register(KEY_URI_2, TOKEN, false, false, Optional.empty());

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
  public void registerUnboundWithHcVault_kmsAeadWorks() throws Exception {
    HcVaultClient.register(KEY_URI, TOKEN, false, false, Optional.empty());

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
    HcVaultClient.register(KEY_URI, TOKEN, false, false, Optional.empty());
    HcVaultClient.register(KEY_URI_2, TOKEN, false, false, Optional.empty());
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
    assertThrows(IllegalArgumentException.class, () -> HcVaultClient.register(invalidUri, TOKEN, false, false, Optional.empty()));
  }
}
