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

package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.DeterministicAead;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AesSiv */
@RunWith(JUnit4.class)
public class AesSivTest {
  @Test
  // Copied from https://tools.ietf.org/html/rfc5297.
  public void testEncryptionWithTestVector() throws GeneralSecurityException {
    AesSiv crypter =
        new AesSiv(Hex.decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
    byte[] pt = Hex.decode("112233445566778899aabbccddee");
    byte[] aad = Hex.decode("101112131415161718191a1b1c1d1e1f2021222324252627");
    byte[] result = crypter.encryptDeterministically(pt, aad);
    String hex = Hex.encode(result);
    System.out.println("result  : " + hex);
    System.out.println("expected: 85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");
    assertEquals("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c", hex);
    byte[] decryptedPt = crypter.decryptDeterministically(result, aad);
    assertEquals("112233445566778899aabbccddee", Hex.encode(decryptedPt));
  }

  @Test
  public void testRepeatedEncryptionWithEmptyPlaintext() throws GeneralSecurityException {
    for (int triesKey = 0; triesKey < 100; triesKey++) {
      DeterministicAead dead = new AesSiv(Random.randBytes(32));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = new byte[0];
        byte[] aad = Random.randBytes(Random.randInt(128) + 1);
        byte[] ciphertext = dead.encryptDeterministically(plaintext, aad);
        byte[] rebuiltPlaintext = dead.decryptDeterministically(ciphertext, aad);
        assertEquals(AesUtil.BLOCK_SIZE, ciphertext.length);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testRepeatedEncryptionWithEmptyAssociatedData() throws GeneralSecurityException {
    for (int triesKey = 0; triesKey < 100; triesKey++) {
      DeterministicAead dead = new AesSiv(Random.randBytes(32));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
        byte[] aad = new byte[0];
        byte[] rebuiltPlaintext =
            dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testRepeatedEncryptionWithEmptyInput() throws GeneralSecurityException {
    for (int triesKey = 0; triesKey < 100; triesKey++) {
      DeterministicAead dead = new AesSiv(Random.randBytes(32));
      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = new byte[0];
        byte[] aad = new byte[0];
        byte[] rebuiltPlaintext =
            dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testRepeatedEncryptions() throws GeneralSecurityException {
    for (int triesKey = 0; triesKey < 100; triesKey++) {
      DeterministicAead dead = new AesSiv(Random.randBytes(32));

      for (int triesPlaintext = 0; triesPlaintext < 100; triesPlaintext++) {
        byte[] plaintext = Random.randBytes(Random.randInt(1024) + 1);
        byte[] aad = Random.randBytes(Random.randInt(128) + 1);
        byte[] rebuiltPlaintext =
            dead.decryptDeterministically(dead.encryptDeterministically(plaintext, aad), aad);
        assertEquals(Hex.encode(plaintext), Hex.encode(rebuiltPlaintext));
      }
    }
  }

  @Test
  public void testModifiedCiphertext() throws GeneralSecurityException {
    byte[] key = Random.randBytes(32);
    DeterministicAead crypter = new AesSiv(key);
    byte[] plaintext = Random.randBytes(10);
    byte[] aad = Random.randBytes(10);
    byte[] ciphertext = crypter.encryptDeterministically(plaintext, aad);
    // Flipping bits of ciphertext.
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = crypter.decryptDeterministically(modified, aad);
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
        byte[] unused = crypter.decryptDeterministically(modified, aad);
        fail("Decrypting modified ciphertext should fail");
      } catch (GeneralSecurityException ex) {
        // This is expected.
        // This could be a AeadBadTagException when the tag verification
        // fails or some not yet specified Exception when the ciphertext is too short.
        // In all cases a GeneralSecurityException or a subclass of it must be thrown.
      }
    }
  }

  @Test
  public void testInvalidKeySizes() throws GeneralSecurityException {
    try {
      new AesSiv(Random.randBytes(16));
    } catch (InvalidKeyException ex) {
      // expected.
    }

    int i = Random.randInt(100);
    if (i == 24 || i == 32) {
      i = Random.randInt(100);
    }

    try {
      new AesSiv(Random.randBytes(i));
    } catch (InvalidKeyException ex) {
      // expected.
    }
  }

  @Test
  public void testInvalidCiphertextSizes() throws GeneralSecurityException {
    byte[] key = Random.randBytes(32);
    DeterministicAead crypter = new AesSiv(key);
    try {
      crypter.decryptDeterministically(Random.randBytes(15), Random.randBytes(20));
    } catch (GeneralSecurityException ex) {
      // expected.
    }
  }

  @Test
  public void testModifiedAssociatedData() throws GeneralSecurityException {
    byte[] key = Random.randBytes(32);
    DeterministicAead crypter = new AesSiv(key);
    byte[] plaintext = Random.randBytes(10);
    byte[] aad = Random.randBytes(10);
    byte[] ciphertext = crypter.encryptDeterministically(plaintext, aad);
    // Flipping bits of aad.
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        try {
          byte[] unused = crypter.decryptDeterministically(ciphertext, modified);
          fail("Decrypting modified aad should fail");
        } catch (AEADBadTagException ex) {
          // This is expected.
        }
      }
    }
  }
}
