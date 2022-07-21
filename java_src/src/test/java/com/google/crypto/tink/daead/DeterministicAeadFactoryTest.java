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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for DeterministicAeadFactory. */
@RunWith(JUnit4.class)
public class DeterministicAeadFactoryTest {

  @BeforeClass
  public static void setUp() throws Exception {
    DeterministicAeadConfig.register();
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedDeterministicAeadFactoryGetPrimitive_sameAs_keysetHandleGetPrimitive()
      throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      // skip all tests.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES256_SIV"));

    DeterministicAead daead = handle.getPrimitive(DeterministicAead.class);
    DeterministicAead factoryDAead = DeterministicAeadFactory.getPrimitive(handle);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] factoryCiphertext = factoryDAead.encryptDeterministically(plaintext, associatedData);

    assertThat(factoryCiphertext).isEqualTo(ciphertext);

    assertThat(daead.decryptDeterministically(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThat(factoryDAead.decryptDeterministically(ciphertext, associatedData))
        .isEqualTo(plaintext);

    byte[] invalid = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class, () -> daead.decryptDeterministically(ciphertext, invalid));
    assertThrows(
        GeneralSecurityException.class,
        () -> factoryDAead.decryptDeterministically(ciphertext, invalid));
    assertThrows(
        GeneralSecurityException.class,
        () -> daead.decryptDeterministically(invalid, associatedData));
    assertThrows(
        GeneralSecurityException.class,
        () -> factoryDAead.decryptDeterministically(invalid, associatedData));
  }
}
