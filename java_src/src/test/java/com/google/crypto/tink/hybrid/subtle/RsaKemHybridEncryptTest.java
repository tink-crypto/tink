// Copyright 2020 Google LLC
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

package com.google.crypto.tink.hybrid.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.aead.subtle.AesGcmFactory;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for RsaKemHybridEncrypt */
@RunWith(JUnit4.class)
public final class RsaKemHybridEncryptTest {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @Test
  public void encrypt_decrypt_success() throws GeneralSecurityException {
    if (TestUtil.isTsan()) {
      // RsaKem.generateRsaKeyPair is too slow in Tsan.
      return;
    }
    KeyPair keyPair = RsaKem.generateRsaKeyPair(2048);
    String hmacAlgo = "HMACSHA256";
    byte[] salt = Random.randBytes(20);

    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    HybridEncrypt hybridEncrypt =
        new RsaKemHybridEncrypt(rsaPublicKey, hmacAlgo, salt, new AesGcmFactory(16));

    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
    HybridDecrypt hybridDecrypt =
        new RsaKemHybridDecrypt(rsaPrivateKey, hmacAlgo, salt, new AesGcmFactory(16));

    byte[] plaintext = Random.randBytes(20);
    byte[] context = Random.randBytes(20);

    // Makes sure that the encryption is randomized.
    Set<String> ciphertexts = new TreeSet<>();
    for (int j = 0; j < 8; j++) {
      byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
      if (ciphertexts.contains(new String(ciphertext, UTF_8))) {
        throw new GeneralSecurityException("Encryption is not randomized");
      }
      ciphertexts.add(new String(ciphertext, UTF_8));
      byte[] decrypted = hybridDecrypt.decrypt(ciphertext, context);
      assertArrayEquals(plaintext, decrypted);
    }
    assertThat(ciphertexts).hasSize(8);
  }

  @Test
  public void constructor_shortKey() throws GeneralSecurityException {
    if (TestUtil.isTsan()) {
      // RsaKem.generateRsaKeyPair is too slow in Tsan.
      return;
    }
    KeyPair keyPair = RsaKem.generateRsaKeyPair(1024);
    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            new RsaKemHybridEncrypt(
                rsaPublicKey, "HMACSHA256", new byte[0], new AesGcmFactory(16)));
  }
}
