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

package com.google.crypto.tink.apps.webpush;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@code WebPushHybridEncrypt}. */
@RunWith(JUnit4.class)
public class WebPushHybridEncryptTest {
  @Test
  public void testEncryptDecrypt() throws Exception {
    KeyPair uaKeyPair = EllipticCurves.generateKeyPair(WebPushConstants.NIST_P256_CURVE_TYPE);
    ECPrivateKey uaPrivateKey = (ECPrivateKey) uaKeyPair.getPrivate();
    ECPublicKey uaPublicKey = (ECPublicKey) uaKeyPair.getPublic();
    byte[] uaPublicKeyBytes =
        EllipticCurves.pointEncode(
            WebPushConstants.NIST_P256_CURVE_TYPE,
            WebPushConstants.UNCOMPRESSED_POINT_FORMAT,
            uaPublicKey.getW());
    byte[] authSecret = Random.randBytes(16);
    HybridEncrypt hybridEncrypt =
        new WebPushHybridEncrypt.Builder()
            .withAuthSecret(authSecret)
            .withRecipientPublicKey(uaPublicKeyBytes)
            .build();
    HybridDecrypt hybridDecrypt =
        new WebPushHybridDecrypt.Builder()
            .withAuthSecret(authSecret)
            .withRecipientPublicKey(uaPublicKeyBytes)
            .withRecipientPrivateKey(uaPrivateKey)
            .build();

    Set<String> salts = new TreeSet<>();
    Set<String> ephemeralPublicKeys = new TreeSet<>();
    Set<String> payloads = new TreeSet<>();
    int numTests = 100;
    if (TestUtil.isTsan()) {
      numTests = 5;
    }
    for (int j = 0; j < numTests; j++) {
      byte[] plaintext = Random.randBytes(j);
      byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null /* contextInfo */);
      assertEquals(ciphertext.length, plaintext.length + WebPushConstants.CIPHERTEXT_OVERHEAD);
      assertArrayEquals(plaintext, hybridDecrypt.decrypt(ciphertext, null /* contextInfo */));

      // Checks that the encryption is randomized.
      ByteBuffer record = ByteBuffer.wrap(ciphertext);
      byte[] salt = new byte[WebPushConstants.SALT_SIZE];
      record.get(salt);
      salts.add(Hex.encode(salt));

      int unused1 = record.getInt();
      int unused2 = (int) record.get();

      byte[] ephemeralPublicKey = new byte[WebPushConstants.PUBLIC_KEY_SIZE];
      record.get(ephemeralPublicKey);
      ephemeralPublicKeys.add(Hex.encode(ephemeralPublicKey));

      byte[] payload = new byte[ciphertext.length - WebPushConstants.CONTENT_CODING_HEADER_SIZE];
      record.get(payload);
      payloads.add(Hex.encode(payload));
    }
    assertEquals(numTests, salts.size());
    assertEquals(numTests, ephemeralPublicKeys.size());
    assertEquals(numTests, payloads.size());
  }

  @Test
  public void testEncryptDecryptWithVaryingRecordSizes() throws Exception {
    KeyPair uaKeyPair = EllipticCurves.generateKeyPair(WebPushConstants.NIST_P256_CURVE_TYPE);
    ECPrivateKey uaPrivateKey = (ECPrivateKey) uaKeyPair.getPrivate();
    ECPublicKey uaPublicKey = (ECPublicKey) uaKeyPair.getPublic();
    byte[] authSecret = Random.randBytes(16);

    int numTests = 100;
    if (TestUtil.isTsan()) {
      numTests = 5;
    }
    // Test with random, valid record sizes.
    for (int i = 0; i < numTests; i++) {
      int recordSize =
          WebPushConstants.CIPHERTEXT_OVERHEAD
              + Random.randInt(
                  WebPushConstants.MAX_CIPHERTEXT_SIZE - WebPushConstants.CIPHERTEXT_OVERHEAD);
      HybridEncrypt hybridEncrypt =
          new WebPushHybridEncrypt.Builder()
              .withRecordSize(recordSize)
              .withAuthSecret(authSecret)
              .withRecipientPublicKey(uaPublicKey)
              .build();
      HybridDecrypt hybridDecrypt =
          new WebPushHybridDecrypt.Builder()
              .withRecordSize(recordSize)
              .withAuthSecret(authSecret)
              .withRecipientPublicKey(uaPublicKey)
              .withRecipientPrivateKey(uaPrivateKey)
              .build();

      byte[] plaintext = Random.randBytes(recordSize - WebPushConstants.CIPHERTEXT_OVERHEAD);
      byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null /* contextInfo */);
      assertEquals(ciphertext.length, plaintext.length + WebPushConstants.CIPHERTEXT_OVERHEAD);
      assertArrayEquals(plaintext, hybridDecrypt.decrypt(ciphertext, null /* contextInfo */));
    }
  }

  @Test
  public void testEncryptDecrypt_largestPossibleRecordSize() throws Exception {
    KeyPair uaKeyPair = EllipticCurves.generateKeyPair(WebPushConstants.NIST_P256_CURVE_TYPE);
    ECPrivateKey uaPrivateKey = (ECPrivateKey) uaKeyPair.getPrivate();
    ECPublicKey uaPublicKey = (ECPublicKey) uaKeyPair.getPublic();
    byte[] authSecret = Random.randBytes(16);
    // Test with largest possible record size.
    HybridEncrypt hybridEncrypt =
        new WebPushHybridEncrypt.Builder()
            .withRecordSize(WebPushConstants.MAX_CIPHERTEXT_SIZE)
            .withAuthSecret(authSecret)
            .withRecipientPublicKey(uaPublicKey)
            .build();
    HybridDecrypt hybridDecrypt =
        new WebPushHybridDecrypt.Builder()
            .withRecordSize(WebPushConstants.MAX_CIPHERTEXT_SIZE)
            .withAuthSecret(authSecret)
            .withRecipientPublicKey(uaPublicKey)
            .withRecipientPrivateKey(uaPrivateKey)
            .build();
    byte[] plaintext =
        Random.randBytes(
            WebPushConstants.MAX_CIPHERTEXT_SIZE - WebPushConstants.CIPHERTEXT_OVERHEAD);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null /* contextInfo */);
    assertEquals(ciphertext.length, plaintext.length + WebPushConstants.CIPHERTEXT_OVERHEAD);
    assertArrayEquals(plaintext, hybridDecrypt.decrypt(ciphertext, null /* contextInfo */));
  }

  @Test
  public void testEncryptDecrypt_smallestPossibleRecordSize() throws Exception {
    KeyPair uaKeyPair = EllipticCurves.generateKeyPair(WebPushConstants.NIST_P256_CURVE_TYPE);
    ECPrivateKey uaPrivateKey = (ECPrivateKey) uaKeyPair.getPrivate();
    ECPublicKey uaPublicKey = (ECPublicKey) uaKeyPair.getPublic();
    byte[] authSecret = Random.randBytes(16);
    // Test with smallest possible record size.
    HybridEncrypt hybridEncrypt =
        new WebPushHybridEncrypt.Builder()
            .withRecordSize(WebPushConstants.CIPHERTEXT_OVERHEAD)
            .withAuthSecret(authSecret)
            .withRecipientPublicKey(uaPublicKey)
            .build();
    HybridDecrypt hybridDecrypt =
        new WebPushHybridDecrypt.Builder()
            .withRecordSize(WebPushConstants.CIPHERTEXT_OVERHEAD)
            .withAuthSecret(authSecret)
            .withRecipientPublicKey(uaPublicKey)
            .withRecipientPrivateKey(uaPrivateKey)
            .build();
    byte[] plaintext = new byte[0];
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null /* contextInfo */);
    assertEquals(ciphertext.length, plaintext.length + WebPushConstants.CIPHERTEXT_OVERHEAD);
    assertArrayEquals(plaintext, hybridDecrypt.decrypt(ciphertext, null /* contextInfo */));
  }

  @Test
  public void testEncryptDecrypt_outOfRangeRecordSize_throws() throws Exception {
    KeyPair uaKeyPair = EllipticCurves.generateKeyPair(WebPushConstants.NIST_P256_CURVE_TYPE);
    ECPublicKey uaPublicKey = (ECPublicKey) uaKeyPair.getPublic();
    byte[] authSecret = Random.randBytes(16);

    try {
      new WebPushHybridEncrypt.Builder()
          .withRecordSize(WebPushConstants.MAX_CIPHERTEXT_SIZE + 1)
          .withAuthSecret(authSecret)
          .withRecipientPublicKey(uaPublicKey)
          .build();
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException ex) {
      // expected.
    }

    try {
      new WebPushHybridEncrypt.Builder()
          .withRecordSize(WebPushConstants.CIPHERTEXT_OVERHEAD - 1)
          .withAuthSecret(authSecret)
          .withRecipientPublicKey(uaPublicKey)
          .build();
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException ex) {
      // expected.
    }
  }

  @Test
  public void testNonNullContextInfo() throws Exception {
    KeyPair uaKeyPair = EllipticCurves.generateKeyPair(WebPushConstants.NIST_P256_CURVE_TYPE);
    ECPublicKey uaPublicKey = (ECPublicKey) uaKeyPair.getPublic();
    byte[] authSecret = Random.randBytes(16);

    HybridEncrypt hybridEncrypt =
        new WebPushHybridEncrypt.Builder()
            .withAuthSecret(authSecret)
            .withRecipientPublicKey(uaPublicKey)
            .build();
    byte[] plaintext = Random.randBytes(20);
    byte[] contextInfo = new byte[0];

    try {
      byte[] unusedCiphertext = hybridEncrypt.encrypt(plaintext, contextInfo);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException ex) {
      // expected;
    }
  }
}

