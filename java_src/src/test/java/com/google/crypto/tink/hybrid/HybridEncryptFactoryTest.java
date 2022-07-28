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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link HybridEncryptFactory}. */
@RunWith(JUnit4.class)
public class HybridEncryptFactoryTest {
  @BeforeClass
  public static void setUp() throws Exception {
    HybridConfig.register();
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedHybridEncryptFactoryGetPrimitive_sameAs_keysetHandleGetPrimitive()
      throws Exception {
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"));
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    HybridEncrypt factoryEncrypter = HybridEncryptFactory.getPrimitive(publicHandle);
    HybridEncrypt handleEncrypter = publicHandle.getPrimitive(HybridEncrypt.class);

    HybridDecrypt decrypter = privateHandle.getPrimitive(HybridDecrypt.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] factoryCiphertext = factoryEncrypter.encrypt(plaintext, contextInfo);
    byte[] handleCiphertext = handleEncrypter.encrypt(plaintext, contextInfo);
    assertThat(decrypter.decrypt(factoryCiphertext, contextInfo)).isEqualTo(plaintext);
    assertThat(decrypter.decrypt(handleCiphertext, contextInfo)).isEqualTo(plaintext);
  }
}
