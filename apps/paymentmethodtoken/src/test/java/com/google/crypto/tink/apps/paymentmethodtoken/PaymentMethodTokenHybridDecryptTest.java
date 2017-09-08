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
import static org.junit.Assert.fail;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Random;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@code PaymentMethodTokenHybridDecrypt}. */
@RunWith(JUnit4.class)
public class PaymentMethodTokenHybridDecryptTest {
  @Test
  public void testModifyDecrypt() throws Exception {
    ECParameterSpec spec = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(spec);
    KeyPair recipientKey = keyGen.generateKeyPair();
    ECPublicKey recipientPublicKey = (ECPublicKey) recipientKey.getPublic();
    ECPrivateKey recipientPrivateKey = (ECPrivateKey) recipientKey.getPrivate();

    HybridEncrypt hybridEncrypt = new PaymentMethodTokenHybridEncrypt(recipientPublicKey);
    HybridDecrypt hybridDecrypt = new PaymentMethodTokenHybridDecrypt(recipientPrivateKey);
    testModifyDecrypt(hybridEncrypt, hybridDecrypt);
  }

  public void testModifyDecrypt(HybridEncrypt hybridEncrypt, HybridDecrypt hybridDecrypt)
      throws Exception {
    byte[] plaintext = Random.randBytes(111);
    byte[] context = "context info".getBytes(StandardCharsets.UTF_8);

    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, context);
    byte[] decrypted = hybridDecrypt.decrypt(ciphertext, context);
    assertArrayEquals(plaintext, decrypted);

    JSONObject json = new JSONObject(new String(ciphertext, StandardCharsets.UTF_8));

    // Modify public key.
    byte[] kem =
        Base64.decode(json.getString(PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY));
    for (int bytes = 0; bytes < kem.length; bytes++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedPublicKey = Arrays.copyOf(kem, kem.length);
        modifiedPublicKey[bytes] ^= (byte) (1 << bit);
        json.put(
            PaymentMethodTokenConstants.JSON_EPHEMERAL_PUBLIC_KEY,
            Base64.encode(modifiedPublicKey));
        try {
          hybridDecrypt.decrypt(json.toString().getBytes(StandardCharsets.UTF_8), context);
          fail("Invalid ciphertext, should have thrown exception");
        } catch (GeneralSecurityException expected) {
          // Expected
        }
      }
    }

    // Modify payload.
    byte[] payload =
        Base64.decode(json.getString(PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY));
    for (int bytes = 0; bytes < payload.length; bytes++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modifiedPayload = Arrays.copyOf(payload, payload.length);
        modifiedPayload[bytes] ^= (byte) (1 << bit);
        json.put(
            PaymentMethodTokenConstants.JSON_ENCRYPTED_MESSAGE_KEY, Base64.encode(modifiedPayload));
        try {
          hybridDecrypt.decrypt(json.toString().getBytes(StandardCharsets.UTF_8), context);
          fail("Invalid ciphertext, should have thrown exception");
        } catch (GeneralSecurityException expected) {
          // Expected
        }
      }
    }

    // Modify context.
    try {
      hybridDecrypt.decrypt(ciphertext, Arrays.copyOf(context, context.length - 1));
      fail("Invalid context, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }
}
