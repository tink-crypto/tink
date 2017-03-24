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

package com.google.cloud.crypto.tink.subtle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;
import javax.crypto.AEADBadTagException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for AesGcm
 * TODO(bleichen): Add more tests.
 *   - maybe add NIST style verification.
 *   - more tests for asynchronous encryption.
 */
@RunWith(JUnit4.class)
public class AesGcmJceTest {

  private static final int[] KEY_SIZES_IN_BYTES = new int[] {16, 24, 32};

  /** Test vectors */
  public static class GcmTestVector {
    final byte[] key;
    final byte[] pt;
    final byte[] aad;
    final byte[] ct;

    public GcmTestVector(
        String message,
        String keyMaterial,
        String aad,
        String ciphertext) {
      this.key = TestUtil.hexDecode(keyMaterial);
      this.pt = TestUtil.hexDecode(message);
      this.aad = TestUtil.hexDecode(aad);
      this.ct = TestUtil.hexDecode(ciphertext);
    }
  };

  private static final GcmTestVector[] GCM_TEST_VECTORS = {
    new GcmTestVector(
        "001d0c231287c1182784554ca3a21908",
        "5b9604fe14eadba931b0ccf34843dab9",
        "",
        "028318abc1824029138141a2"
           + "26073cc1d851beff176384dc9896d5ff"
           + "0a3ea7a5487cb5f7d70fb6c58d038554"),
    new GcmTestVector(
        "2035af313d1346ab00154fea78322105",
        "aa023d0478dcb2b2312498293d9a9129",
        "aac39231129872a2",
        "0432bc49ac34412081288127"
            + "eea945f3d0f98cc0fbab472a0cf24e87"
            + "4bb9b4812519dadf9e1232016d068133"),
    // key size:256
    new GcmTestVector(
        "00010203040506070809",
        "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20",
        "00000000ffffffff",
        "00112233445566778899aabb"
            + "e27abdd2d2a53d2f136b"
            + "9a4a2579529301bcfb71c78d4060f52c"),
    new GcmTestVector(
        "",
        "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123",
        "aabbccddeeff",
        "00112233445566778899aabb"
            + "2a7d77fa526b8250cb296078926b5020"),

    // special cases
    new GcmTestVector(
        "7fd49ba712d0d28f02ef54ed18db43f8",
        "00112233445566778899aabbccddeeff",
        "",
        "00112233445566778899aabb"
            + "d8eba6a5a03403851abc27f6e15d84c0"
            + "00000000000000000000000000000000"),
   new GcmTestVector(
        "ebd4a3e10cf6d41c50aeae007563b072",
        "00112233445566778899aabbccddeeff",
        "",
        "000000000000000000000000"
            + "f62d84d649e56bc8cfedc5d74a51e2f7"
            + "ffffffffffffffffffffffffffffffff"),
    new GcmTestVector(
        "d593c4d8224f1b100c35e4f6c4006543",
        "00112233445566778899aabbccddeeff",
        "",
        "ffffffffffffffffffffffff"
            + "431f31e6840931fd95f94bf88296ff69"
            + "00000000000000000000000000000000"),
  };

  @Test
  /**
   * A regression test with some test vectors.
   * AesGcmJce randomizes the ciphertext. Therefore this test only
   * checks that decryption still works.
   */
  public void testRegression() throws Exception {
    for (GcmTestVector test : GCM_TEST_VECTORS) {
      AesGcmJce gcm = new AesGcmJce(test.key);
      byte[] pt = gcm.decrypt(test.ct, test.aad);
      assertArrayEquals(test.pt, pt);
    }
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    byte[] aad = new byte[] {1, 2, 3};
    for (int keySize : KEY_SIZES_IN_BYTES) {
      byte[] key = Random.randBytes(keySize);
      AesGcmJce gcm = new AesGcmJce(key);
      for (int messageSize = 0; messageSize < 75; messageSize++) {
        byte[] message = Random.randBytes(messageSize);
        byte[] ciphertext = gcm.encrypt(message, aad);
        byte[] decrypted = gcm.decrypt(ciphertext, aad);
        assertArrayEquals(message, decrypted);
      }
    }
  }

  @Test
  /**
   * BC had a bug, where GCM failed for messages of size > 8192
   */
  public void testLongMessages() throws Exception {
    int dataSize = 16;
    while (dataSize <= (1 << 24)) {
      byte[] plaintext = Random.randBytes(dataSize);
      byte[] aad = Random.randBytes(dataSize / 3);
      for (int keySize : KEY_SIZES_IN_BYTES) {
        byte[] key = Random.randBytes(keySize);
        AesGcmJce gcm = new AesGcmJce(key);
        byte[] ciphertext = gcm.encrypt(plaintext, aad);
        byte[] decrypted = gcm.decrypt(ciphertext, aad);
        assertArrayEquals(plaintext, decrypted);
      }
      dataSize += 5 * dataSize / 11;
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    byte[] aad = Random.randBytes(33);
    byte[] key = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    AesGcmJce gcm = new AesGcmJce(key);
    byte[] ciphertext = gcm.encrypt(message, aad);

    // Flipping bits
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = gcm.decrypt(modified, aad);
          fail("Decrypting modified ciphertext should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }

    // Truncate the message.
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] modified = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = gcm.decrypt(modified, aad);
        fail("Decrypting modified ciphertext should fail");
      } catch (GeneralSecurityException ex) {
        // This is expected.
        // This could be a AeadBadTagException when the tag verification
        // fails or some not yet specified Exception when the ciphertext is too short.
        // In all cases a GeneralSecurityException or a subclass of it must be thrown.
      }
    }

    // Modify AAD
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = gcm.decrypt(ciphertext, modified);
          fail("Decrypting with modified aad should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }
  }

  @Test
  /**
   * This is a very simple test for the randomness of the nonce.
   * The test simply checks that the multiple ciphertexts of the same
   * message are distinct.
   */
  public void testRandomNonce() throws Exception {
     final int samples = 1 << 17;
     byte[] key = Random.randBytes(16);
     byte[] message = new byte[0];
     byte[] aad = new byte[0];
     AesGcmJce gcm = new AesGcmJce(key);
     HashSet<String> ciphertexts = new HashSet<String>();
     for (int i = 0; i < samples; i++) {
       byte[] ct = gcm.encrypt(message, aad);
       String ctHex = TestUtil.hexEncode(ct);
       assertFalse(ciphertexts.contains(ctHex));
       ciphertexts.add(ctHex);
     }
  }

  @Test
  /**
   * A very basic test for asynchronous encryption.
   */
  public void testAsync() throws Exception {
    byte[] aad = new byte[] {1, 2, 3};
    byte[] key = Random.randBytes(16);
    AesGcmJce gcm = new AesGcmJce(key);
    byte[] plaintext = Random.randBytes(20);

    byte[] ciphertext = gcm.asyncEncrypt(plaintext, aad).get();
    byte[] decrypted = gcm.asyncDecrypt(ciphertext, aad).get();
    assertArrayEquals(plaintext, decrypted);
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] truncated = Arrays.copyOf(ciphertext, length);
      try {
        byte[] unused = gcm.asyncDecrypt(truncated, aad).get();
        fail("Decrypting a truncated ciphertext should fail");
      } catch (ExecutionException ex) {
        // The decryption should fail because the ciphertext has been truncated.
        assertTrue(ex.getCause() instanceof GeneralSecurityException);
      }
    }
  }
}
