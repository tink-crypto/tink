// Copyright 2022 Google LLC
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
import com.google.crypto.tink.aead.AeadConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit test for {@link HybridEncryptFactory} and {@link HybridDecrytFactory}.
 *
 * <p>The test case in this file needs {@link Registry} to not have HybridDecrytWrapper registered.
 * That's why it is in its own test file.
 */
@RunWith(JUnit4.class)
public class HybridEncryptDecryptFactoryWithoutWrapperRegisteredTest {

  @Test
  @SuppressWarnings("deprecation") // This is a test that the deprecated function works.
  public void deprecatedFactoryGetPrimitive_whenWrapperHasNotBeenRegistered_works()
      throws Exception {
    AeadConfig.register();
    // Only register EciesAeadHkdfPrivateKeyManager, but not HybridEncryptWrapper and
    // HybridDecryptWrapper.
    EciesAeadHkdfPrivateKeyManager.registerPair(/*newKeyAllowed=*/ true);
    KeysetHandle privateHandle =
        KeysetHandle.generateNew(KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"));
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    HybridEncrypt encrypter = HybridEncryptFactory.getPrimitive(publicHandle);
    HybridDecrypt decrypter = HybridDecryptFactory.getPrimitive(privateHandle);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] contextInfo = "contextInfo".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(plaintext, contextInfo);
    assertThat(decrypter.decrypt(ciphertext, contextInfo)).isEqualTo(plaintext);
  }
}
