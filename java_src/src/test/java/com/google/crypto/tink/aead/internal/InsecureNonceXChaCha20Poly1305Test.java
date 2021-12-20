// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for InsecureNonceXChaCha20Poly1305. */
@RunWith(JUnit4.class)
public class InsecureNonceXChaCha20Poly1305Test {
  private static final int KEY_SIZE_IN_BYTES = 32;

  private static class XChaCha20Poly1305TestVector {
    public byte[] key;
    public byte[] nonce;
    public byte[] plaintext;
    public byte[] aad;
    public byte[] ciphertext;
    public byte[] tag;

    public XChaCha20Poly1305TestVector(
        String key, String nonce, String plaintext, String aad, String ciphertext, String tag) {
      this.key = Hex.decode(key);
      this.nonce = Hex.decode(nonce);
      this.plaintext = Hex.decode(plaintext);
      this.aad = Hex.decode(aad);
      this.ciphertext = Hex.decode(ciphertext);
      this.tag = Hex.decode(tag);
    }
  }

  private static final XChaCha20Poly1305TestVector[] xChaCha20Poly1305TestVectors = {
    // From libsodium's test/default/aead_xchacha20poly1305.c
    // see test/default/aead_xchacha20poly1305.exp for ciphertext values.
    new XChaCha20Poly1305TestVector(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "07000000404142434445464748494a4b0000000000000000",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620"
            + "4920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574"
            + "7572652c2073756e73637265656e20776f756c642062652069742e",
        "50515253c0c1c2c3c4c5c6c7",
        "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8b89ad929530a1bb3ab5e69f24c"
            + "7f6070c8f840c9abb4f69fbfc8a7ff5126faeebbb55805ee9c1cf2ce5a57263287aec5780f04ec324c35"
            + "14122cfc3231fc1a8b718a62863730a2702bb76366116bed09e0fd",
        "5c6d84b6b0c1abaf249d5dd0f7f5a7ea"),
    new XChaCha20Poly1305TestVector(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "07000000404142434445464748494a4b0000000000000000",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620"
            + "4920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574"
            + "7572652c2073756e73637265656e20776f756c642062652069742e",
        "" /* empty aad */,
        "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8b89ad929530a1bb3ab5e69f24c"
            + "7f6070c8f840c9abb4f69fbfc8a7ff5126faeebbb55805ee9c1cf2ce5a57263287aec5780f04ec324c35"
            + "14122cfc3231fc1a8b718a62863730a2702bb76366116bed09e0fd",
        "d4c860b7074be894fac9697399be5cc1"),
    // From  https://tools.ietf.org/html/draft-arciszewski-xchacha-01.
    new XChaCha20Poly1305TestVector(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "404142434445464748494a4b4c4d4e4f5051525354555657",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620"
            + "4920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574"
            + "7572652c2073756e73637265656e20776f756c642062652069742e",
        "50515253c0c1c2c3c4c5c6c7",
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4e"
            + "da7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc36948"
            + "8f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
        "c0875924c1c7987947deafd8780acf49")
  };

  @Test
  public void testXChaCha20Poly1305TestVectors() throws Exception {
    for (XChaCha20Poly1305TestVector test : xChaCha20Poly1305TestVectors) {
      InsecureNonceXChaCha20Poly1305 cipher = new InsecureNonceXChaCha20Poly1305(test.key);
      byte[] message =
          cipher.decrypt(test.nonce, Bytes.concat(test.ciphertext, test.tag), test.aad);
      assertThat(message).isEqualTo(test.plaintext);
    }
  }

  @Test
  public void testSnufflePoly1305ThrowsIllegalArgExpWhenKeyLenIsGreaterThan32()
      throws GeneralSecurityException {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new InsecureNonceXChaCha20Poly1305(new byte[KEY_SIZE_IN_BYTES + 1]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testSnufflePoly1305ThrowsIllegalArgExpWhenKeyLenIsLessThan32()
      throws GeneralSecurityException {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new InsecureNonceXChaCha20Poly1305(new byte[KEY_SIZE_IN_BYTES - 1]));
    assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort()
      throws GeneralSecurityException {
    InsecureNonceXChaCha20Poly1305 cipher =
        new InsecureNonceXChaCha20Poly1305(new byte[KEY_SIZE_IN_BYTES]);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                cipher.decrypt(
                    new byte[24],
                    // NOTE: Valid ciphertext must contain enough bytes for the tag.
                    new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES - 1],
                    new byte[1]));
    assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    InsecureNonceXChaCha20Poly1305 cipher =
        new InsecureNonceXChaCha20Poly1305(Random.randBytes(KEY_SIZE_IN_BYTES));
    for (int i = 0; i < 100; i++) {
      byte[] message = Random.randBytes(i);
      byte[] aad = Random.randBytes(i);
      byte[] nonce = Random.randBytes(24);
      byte[] ciphertext = cipher.encrypt(nonce, message, aad);
      byte[] decrypted = cipher.decrypt(nonce, ciphertext, aad);
      assertArrayEquals(message, decrypted);
    }
  }

  @Test
  public void testLongMessages() throws Exception {
    if (TestUtil.isAndroid() || TestUtil.isTsan()) {
      System.out.println("testLongMessages doesn't work on Android and under tsan, skipping");
      return;
    }
    int dataSize = 16;
    while (dataSize <= (1 << 24)) {
      byte[] plaintext = Random.randBytes(dataSize);
      byte[] aad = Random.randBytes(dataSize / 3);
      byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
      InsecureNonceXChaCha20Poly1305 cipher = new InsecureNonceXChaCha20Poly1305(key);
      byte[] nonce = Random.randBytes(24);
      byte[] ciphertext = cipher.encrypt(nonce, plaintext, aad);
      byte[] decrypted = cipher.decrypt(nonce, ciphertext, aad);
      assertArrayEquals(plaintext, decrypted);
      dataSize += 5 * dataSize / 11;
    }
  }

  @Test
  public void testModifyCiphertext() throws Exception {
    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    InsecureNonceXChaCha20Poly1305 cipher = new InsecureNonceXChaCha20Poly1305(key);
    byte[] aad = Random.randBytes(16);
    byte[] message = Random.randBytes(32);
    byte[] nonce = Random.randBytes(24);
    byte[] ciphertext = cipher.encrypt(nonce, message, aad);

    // Flipping bits
    for (int b = 0; b < ciphertext.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(ciphertext, ciphertext.length);
        modified[b] ^= (byte) (1 << bit);
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = cipher.decrypt(nonce, modified, aad);
            });
      }
    }

    // Truncate the message.
    for (int length = 0; length < ciphertext.length; length++) {
      byte[] modified = Arrays.copyOf(ciphertext, length);
      assertThrows(
          GeneralSecurityException.class,
          () -> {
            byte[] unused = cipher.decrypt(nonce, modified, aad);
          });
    }

    // Modify AAD
    for (int b = 0; b < aad.length; b++) {
      for (int bit = 0; bit < 8; bit++) {
        byte[] modified = Arrays.copyOf(aad, aad.length);
        modified[b] ^= (byte) (1 << bit);
        assertThrows(
            AEADBadTagException.class,
            () -> {
              byte[] unused = cipher.decrypt(nonce, ciphertext, modified);
            });
      }
    }
  }

  /** This test simply checks that the same nonce for a given input produces the same output. */
  @Test
  public void testSameNonce() throws Exception {
    byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
    InsecureNonceXChaCha20Poly1305 cipher = new InsecureNonceXChaCha20Poly1305(key);
    byte[] message = new byte[0];
    byte[] aad = new byte[0];
    byte[] nonce = Random.randBytes(24);

    byte[] ct = cipher.encrypt(nonce, message, aad);
    byte[] ct2 = cipher.encrypt(nonce, message, aad);
    byte[] pt = cipher.decrypt(nonce, ct, aad);
    byte[] pt2 = cipher.decrypt(nonce, ct, aad);

    assertArrayEquals(ct, ct2);
    assertArrayEquals(pt, pt2);
  }
}
