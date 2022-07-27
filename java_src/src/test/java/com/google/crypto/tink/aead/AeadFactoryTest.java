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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AeadFactory. */
@RunWith(JUnit4.class)
public class AeadFactoryTest {

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedAeadFactoryGetPrimitive_sameAs_keysetHandleGetPrimitive() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES128_CTR_HMAC_SHA256"));

    Aead aead = handle.getPrimitive(Aead.class);
    Aead factoryAead = AeadFactory.getPrimitive(handle);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] factoryCiphertext = aead.encrypt(plaintext, associatedData);

    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThat(aead.decrypt(factoryCiphertext, associatedData)).isEqualTo(plaintext);
    assertThat(factoryAead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThat(factoryAead.decrypt(factoryCiphertext, associatedData)).isEqualTo(plaintext);

    byte[] invalid = "invalid".getBytes(UTF_8);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, invalid));
    assertThrows(GeneralSecurityException.class, () -> factoryAead.decrypt(ciphertext, invalid));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(invalid, associatedData));
    assertThrows(
        GeneralSecurityException.class, () -> factoryAead.decrypt(invalid, associatedData));
  }
}
