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

package com.google.crypto.tink.integration.gcpkms;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.KmsAeadKeyManager;
import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Integration tests for Tink's GcpKmsClient with the real GCP Cloud KMS. */
@RunWith(JUnit4.class)
public class GcpKmsIntegrationTest {
  @Before
  public void setUp() throws Exception {
    GcpKmsClient.register(Optional.empty(), Optional.of(TestUtil.SERVICE_ACCOUNT_FILE));
    AeadConfig.register();
  }

  @Test
  public void kmsAead_encryptDecrypt() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.generateNew(
            KmsAeadKeyManager.createKeyTemplate(TestUtil.GCP_KMS_TEST_KEY_URI));

    Aead aead = keysetHandle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    byte[] invalid = "invalid".getBytes(UTF_8);
    byte[] empty = "".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, invalid));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(invalid, associatedData));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(empty, associatedData));
    assertThat(aead.decrypt(aead.encrypt(empty, associatedData), associatedData)).isEqualTo(empty);
    assertThat(aead.decrypt(aead.encrypt(plaintext, empty), empty)).isEqualTo(plaintext);
  }

  @Test
  public void kmsEnvelopeAead_encryptDecrypt() throws Exception {
    KeyTemplate envelopeTemplate =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            TestUtil.GCP_KMS_TEST_KEY_URI, KeyTemplates.get("AES128_CTR_HMAC_SHA256"));
    KeysetHandle keysetHandle = KeysetHandle.generateNew(envelopeTemplate);

    Aead aead = keysetHandle.getPrimitive(Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);

    byte[] invalid = "invalid".getBytes(UTF_8);
    byte[] empty = "".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, invalid));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(invalid, associatedData));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(empty, associatedData));
    assertThat(aead.decrypt(aead.encrypt(empty, associatedData), associatedData)).isEqualTo(empty);
    assertThat(aead.decrypt(aead.encrypt(plaintext, empty), empty)).isEqualTo(plaintext);
  }
}
