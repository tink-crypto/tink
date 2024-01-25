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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.Random;
import io.github.jopenlibs.vault.api.Logical;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HcVaultAead. */
@RunWith(JUnit4.class)
public class HcVaultAeadTest {
  private static final String KEY_URI = "hcvault://hcvault.corp.com:8200/transit/keys/key-1";
  private static final String KEY_URI_2 = "hcvault://hcvault.corp.com:8200/transit/keys/key-2";
  private static final String INVALID_KEY = "hcvaul://hcvault.corp.com:8200/transit/keys/invalid";

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testEncryptDecryptWithKnownKeyArn_success() throws Exception {
    Logical kms = FakeHcVault.fromURI(KEY_URI);

    Aead aead = new HcVaultAead(kms, KEY_URI);
    byte[] aad = Random.randBytes(20);
    byte[] message = "testencrypt1".getBytes();
    byte[] ciphertext = aead.encrypt(message, aad);
    byte[] decrypted = aead.decrypt(ciphertext, aad);
    assertThat(decrypted).isEqualTo(message);
  }

  @Test
  public void testEncryptWithUnknownKeyArn_fails() throws Exception {
    Logical invalidKms = FakeHcVault.fromURI(INVALID_KEY);

    Aead aead = new HcVaultAead(invalidKms, INVALID_KEY);
    byte[] aad = Random.randBytes(20);
    byte[] message = "testencrypt2".getBytes();
    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(message, aad));
  }

  @Test
  public void testDecryptWithInvalidKeyArn_fails() throws Exception {
    Logical kms = FakeHcVault.fromURI(INVALID_KEY);
    Aead aead = new HcVaultAead(kms, INVALID_KEY);
    byte[] aad = Random.randBytes(20);
    byte[] invalidCiphertext = Random.randBytes(2);
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(invalidCiphertext, aad));
  }

  @Test
  public void testDecryptWithDifferentKeyArn_fails() throws Exception {
    Logical kms1 = FakeHcVault.fromURI(KEY_URI);
    Logical kms2 = FakeHcVault.fromURI(KEY_URI_2);

    Aead aead = new HcVaultAead(kms1, KEY_URI);
    byte[] aad = Random.randBytes(20);
    byte[] message = "testencrypt3".getBytes();

    // Create a valid ciphertext with a different URI
    Aead aeadWithDifferentArn = new HcVaultAead(kms2, KEY_URI_2);
    byte[] ciphertextFromDifferentArn = aeadWithDifferentArn.encrypt(message, aad);

    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertextFromDifferentArn, aad));
  }
}
