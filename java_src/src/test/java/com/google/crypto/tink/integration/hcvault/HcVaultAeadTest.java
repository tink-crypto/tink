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
import static java.util.Arrays.asList;
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
  private static final String KEY_PATH = "transit/keys/key-1";
  private static final String KEY_PATH_2 = "transit/keys/key-2";
  private static final String INVALID_KEY_PATH = "invalid-path";

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testEncryptDecryptWithValidKey_success() throws Exception {
    Logical kms =
        new FakeHcVault(/* mountPath= */ "transit", /* validKeyNames= */ asList("key-1", "key-2"));

    Aead aead = HcVaultAead.newAead(KEY_PATH, kms);
    byte[] aad = Random.randBytes(20);
    byte[] message = "testencrypt1".getBytes();
    byte[] ciphertext = aead.encrypt(message, aad);
    byte[] decrypted = aead.decrypt(ciphertext, aad);
    assertThat(decrypted).isEqualTo(message);
  }

  @Test
  public void testNewWithInvalidKey_fails() throws Exception {
    Logical kms =
        new FakeHcVault(/* mountPath= */ "transit", /* validKeyNames= */ asList("key-1", "key-2"));
    assertThrows(GeneralSecurityException.class, () -> HcVaultAead.newAead(INVALID_KEY_PATH, kms));
  }

  @Test
  public void testDecryptWithDifferentKey_worksButShouldFails() throws Exception {
    Logical kms =
        new FakeHcVault(/* mountPath= */ "transit", /* validKeyNames= */ asList("key-1", "key-2"));

    Aead aead = HcVaultAead.newAead(KEY_PATH, kms);
    byte[] aad = Random.randBytes(20);
    byte[] message = "testencrypt3".getBytes();

    // Create a valid ciphertext with a different key
    Aead aead2 = HcVaultAead.newAead(KEY_PATH_2, kms);
    byte[] ciphertext2 = aead2.encrypt(message, aad);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext2, aad));
  }

  @Test
  public void getOperationEndpoint_valid() throws Exception {
    assertThat(HcVaultAead.getOperationEndpoint("transit/keys/key-1", "encrypt"))
        .isEqualTo(("transit/encrypt/key-1"));
    assertThat(HcVaultAead.getOperationEndpoint("transit/keys/this%2Band+that", "encrypt"))
        .isEqualTo(("transit/encrypt/this%2Band+that"));
    assertThat(
            HcVaultAead.getOperationEndpoint(
                "teams/billing/something/transit/keys/pci-key", "decrypt"))
        .isEqualTo(("teams/billing/something/transit/decrypt/pci-key"));
    assertThat(
            HcVaultAead.getOperationEndpoint(
                "transit/keys/something/transit/keys/my-key", "decrypt"))
        .isEqualTo(("transit/keys/something/transit/decrypt/my-key"));
    assertThat(HcVaultAead.getOperationEndpoint("cipher/keys/hi", "decrypt"))
        .isEqualTo(("cipher/decrypt/hi"));
  }

  @Test
  public void getOperationEndpoint_invalid() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> HcVaultAead.getOperationEndpoint("", "encrypt"));
    assertThrows(
        GeneralSecurityException.class, () -> HcVaultAead.getOperationEndpoint("/", "encrypt"));
    assertThrows(
        GeneralSecurityException.class,
        () -> HcVaultAead.getOperationEndpoint("transit/keys/invalid/keyname", "encrypt"));
  }
}
