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

package com.google.crypto.tink.apps.paymentmethodtoken;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Random;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@code PaymentMethodTokenHybridEncrypt}. */
@RunWith(JUnit4.class)
public class PaymentMethodTokenHybridEncryptTest {
  @Test
  public void testBasicMultipleEncrypts() throws Exception {
    ECParameterSpec spec = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(spec);
    KeyPair recipientKey = keyGen.generateKeyPair();
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();

    HybridEncrypt hybridEncrypt = new PaymentMethodTokenHybridEncrypt(recipientPublicKey);
    HybridDecrypt hybridDecrypt = new PaymentMethodTokenHybridDecrypt(recipientPrivateKey);
    testBasicMultipleEncrypts(hybridEncrypt, hybridDecrypt);
  }

  public void testBasicMultipleEncrypts(HybridEncrypt hybridEncrypt, HybridDecrypt hybridDecrypt)
      throws Exception {
    byte[] plaintext = Random.randBytes(111);
    byte[] context = "context info".getBytes(StandardCharsets.UTF_8);
    // Makes sure that the encryption is randomized.
    Set<String> ciphertexts = new TreeSet<String>();
    for (int j = 0; j < 100; j++) {
      byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
      if (ciphertexts.contains(new String(ciphertext, StandardCharsets.UTF_8))) {
        throw new GeneralSecurityException("Encryption is not randomized");
      }
      ciphertexts.add(new String(ciphertext, StandardCharsets.UTF_8));
      byte[] decrypted = hybridDecrypt.decrypt(ciphertext, context);
      assertArrayEquals(plaintext, decrypted);
    }
    assertEquals(100, ciphertexts.size());
  }
}
