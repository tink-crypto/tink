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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.common.truth.Truth;
import com.google.crypto.tink.TestUtil;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for DjbCipherPoly1305.
 */
@RunWith(JUnit4.class)
public class DjbCipherPoly1305Test {

  /**
   * Tests against the test vectors in Section 2.5.2 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#section-2.5.2
   */
  @Test
  public void testChaChaPoly1305() {
    byte[] key = TestUtil.hexDecode(""
        + "85d6be7857556d337f4452fe42d506a8"
        + "0103808afb0db2fd4abff6af4149f51b");
    byte[] in = ("Cryptographic Forum Research Group").getBytes(StandardCharsets.US_ASCII);
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "a8061dc1305136c6c22b8baf0c0127a9"));
  }

  /**
   * Tests against the test vectors in Section 2.6.2 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#section-2.6.2
   */
  @Test
  public void testChaChaPoly1305KeyGen() {
    byte[] key = TestUtil.hexDecode(""
        + "808182838485868788898a8b8c8d8e8f"
        + "909192939495969798999a9b9c9d9e9f");
    byte[] nonce = TestUtil.hexDecode("000000000001020304050607");
    ChaCha20 cipher = new ChaCha20(key);
    Truth.assertThat(cipher.getAeadSubKey(nonce)).isEqualTo(TestUtil.hexDecode(""
        + "8ad5a08b905f81cc815040274ab29471"
        + "a833b637e3fd0da508dbb8e2fdd1a646"));
  }

  /**
   * Tests against the test vectors in Section 2.8.2 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#section-2.8.2
   */
  @Test
  public void testChaChaPoly1305Decrypt() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "808182838485868788898a8b8c8d8e8f"
        + "909192939495969798999a9b9c9d9e9f");
    byte[] ciphertext = TestUtil.hexDecode(""
        + "1ae10b594f09e26a7e902ecbd0600691"  // tag
        + "070000004041424344454647"          // nonce
        + "d31a8d34648e60db7b86afbc53ef7ec2"  // ciphertext
        + "a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b"
        + "1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58"
        + "fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b"
        + "6116");
    byte[] aad = TestUtil.hexDecode("50515253c0c1c2c3c4c5c6c7");
    DjbCipherPoly1305 aead = DjbCipherPoly1305.constructChaCha20Poly1305(key);
    Truth.assertThat(aead.decrypt(ciphertext, aad)).isEqualTo(
        ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
            + "future, sunscreen would be it.").getBytes(StandardCharsets.US_ASCII));
  }

  @Test
  public void testDecryptThrowsGeneralSecurityExpForCorruptInput() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "808182838485868788898a8b8c8d8e8f"
        + "909192939495969798999a9b9c9d9e9f");
    byte[] ciphertext = TestUtil.hexDecode(""
        + "1ae10b594f09e26a7e902ecbd0600692"  // corrupt tag
        + "070000004041424344454647"          // nonce
        + "d31a8d34648e60db7b86afbc53ef7ec2"  // ciphertext
        + "a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b"
        + "1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58"
        + "fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b"
        + "6116");
    byte[] aad = TestUtil.hexDecode("50515253c0c1c2c3c4c5c6c7");
    try {
      DjbCipherPoly1305.constructChaCha20Poly1305(key).decrypt(ciphertext, aad);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      Truth.assertThat(e).hasMessageThat().containsMatch("Tags do not match.");
    }

  }

  /**
   * Tests against the test vector 1 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector1() {
    byte[] key = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "00000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 2 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector2() {
    byte[] key = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "36e5f6b5c5e06070f0efca96227a863e");
    byte[] in = ("Any submission to the IETF intended by the Contributor for publication as all or "
        + "part of an IETF Internet-Draft or RFC and any statement made within the context of an "
        + "IETF activity is considered an \"IETF Contribution\". Such statements include oral "
        + "statements in IETF sessions, as well as written and electronic communications made at "
        + "any time or place, which are addressed to")
        .getBytes(StandardCharsets.US_ASCII);
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "36e5f6b5c5e06070f0efca96227a863e"));
  }

  /**
   * Tests against the test vector 3 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector3() {
    byte[] key = TestUtil.hexDecode(""
        + "36e5f6b5c5e06070f0efca96227a863e"
        + "00000000000000000000000000000000");
    byte[] in = ("Any submission to the IETF intended by the Contributor for publication as all or "
        + "part of an IETF Internet-Draft or RFC and any statement made within the context of an "
        + "IETF activity is considered an \"IETF Contribution\". Such statements include oral "
        + "statements in IETF sessions, as well as written and electronic communications made at "
        + "any time or place, which are addressed to")
        .getBytes(StandardCharsets.US_ASCII);
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "f3477e7cd95417af89a6b8794c310cf0"));
  }

  /**
   * Tests against the test vector 4 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector4() {
    byte[] key = TestUtil.hexDecode(""
        + "1c9240a5eb55d38af333888604f6b5f0"
        + "473917c1402b80099dca5cbc207075c0");
    byte[] in = TestUtil.hexDecode(""
        + "2754776173206272696c6c69672c2061"
        + "6e642074686520736c6974687920746f"
        + "7665730a446964206779726520616e64"
        + "2067696d626c6520696e207468652077"
        + "6162653a0a416c6c206d696d73792077"
        + "6572652074686520626f726f676f7665"
        + "732c0a416e6420746865206d6f6d6520"
        + "7261746873206f757467726162652e");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "4541669a7eaaee61e708dc7cbcc5eb62"));
  }

  /**
   * Tests against the test vector 5 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector5() {
    byte[] key = TestUtil.hexDecode(""
        + "02000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "ffffffffffffffffffffffffffffffff");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "03000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 6 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector6() {
    byte[] key = TestUtil.hexDecode(""
        + "02000000000000000000000000000000"
        + "ffffffffffffffffffffffffffffffff");
    byte[] in = TestUtil.hexDecode(""
        + "02000000000000000000000000000000");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "03000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 7 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector7() {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "ffffffffffffffffffffffffffffffff"
        + "f0ffffffffffffffffffffffffffffff"
        + "11000000000000000000000000000000");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "05000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 8 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector8() {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "ffffffffffffffffffffffffffffffff"
        + "fbfefefefefefefefefefefefefefefe"
        + "01010101010101010101010101010101");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "00000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 9 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector9() {
    byte[] key = TestUtil.hexDecode(""
        + "02000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "fdffffffffffffffffffffffffffffff");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "faffffffffffffffffffffffffffffff"));
  }

  /**
   * Tests against the test vector 10 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector10() {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000400000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "e33594d7505e43b90000000000000000"
        + "3394d7505e4379cd0100000000000000"
        + "00000000000000000000000000000000"
        + "01000000000000000000000000000000");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "14000000000000005500000000000000"));
  }

  /**
   * Tests against the test vector 11 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testChaChaPoly1305TestVector11() {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000400000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "e33594d7505e43b90000000000000000"
        + "3394d7505e4379cd0100000000000000"
        + "00000000000000000000000000000000");
    byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
    Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
        + "13000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 1 in Appendix A.4 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.4
   */
  @Test
  public void testChaChaPoly1305KeyGen1() {
    byte[] key = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] nonce = TestUtil.hexDecode("000000000000000000000000");
    ChaCha20 cipher = new ChaCha20(key);
    Truth.assertThat(cipher.getAeadSubKey(nonce)).isEqualTo(TestUtil.hexDecode(""
        + "76b8e0ada0f13d90405d6ae55386bd28"
        + "bdd219b8a08ded1aa836efcc8b770dc7"));
  }

  /**
   * Tests against the test vector 2 in Appendix A.4 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.4
   */
  @Test
  public void testChaChaPoly1305KeyGen2() {
    byte[] key = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000001");
    byte[] nonce = TestUtil.hexDecode("000000000000000000000002");
    ChaCha20 cipher = new ChaCha20(key);
    Truth.assertThat(cipher.getAeadSubKey(nonce)).isEqualTo(TestUtil.hexDecode(""
        + "ecfa254f845f647473d3cb140da9e876"
        + "06cb33066c447b87bc2666dde3fbb739"));
  }

  /**
   * Tests against the test vector 3 in Appendix A.4 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.4
   */
  @Test
  public void testChaChaPoly1305KeyGen3() {
    byte[] key = TestUtil.hexDecode(""
        + "1c9240a5eb55d38af333888604f6b5f0"
        + "473917c1402b80099dca5cbc207075c0");
    byte[] nonce = TestUtil.hexDecode("000000000000000000000002");
    ChaCha20 cipher = new ChaCha20(key);
    Truth.assertThat(cipher.getAeadSubKey(nonce)).isEqualTo(TestUtil.hexDecode(""
        + "965e3bc6f9ec7ed9560808f4d229f94b"
        + "137ff275ca9b3fcbdd59deaad23310ae"));
  }

  /**
   * Tests against the test vector in Appendix A.5 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.5
   */
  @Test
  public void testChaChaPoly1305AeadDecryption() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "1c9240a5eb55d38af333888604f6b5f0"
        + "473917c1402b80099dca5cbc207075c0");
    byte[] ciphertext = TestUtil.hexDecode(""
        + "eead9d67890cbb22392336fea1851f38"  // tag
        + "000000000102030405060708"          // nonce
        + "64a0861575861af460f062c79be643bd"  // ciphertext
        + "5e805cfd345cf389f108670ac76c8cb2"
        + "4c6cfc18755d43eea09ee94e382d26b0"
        + "bdb7b73c321b0100d4f03b7f355894cf"
        + "332f830e710b97ce98c8a84abd0b9481"
        + "14ad176e008d33bd60f982b1ff37c855"
        + "9797a06ef4f0ef61c186324e2b350638"
        + "3606907b6a7c02b0f9f6157b53c867e4"
        + "b9166c767b804d46a59b5216cde7a4e9"
        + "9040c5a40433225ee282a1b0a06c523e"
        + "af4534d7f83fa1155b0047718cbc546a"
        + "0d072b04b3564eea1b422273f548271a"
        + "0bb2316053fa76991955ebd63159434e"
        + "cebb4e466dae5a1073a6727627097a10"
        + "49e617d91d361094fa68f0ff77987130"
        + "305beaba2eda04df997b714d6c6f2c29"
        + "a6ad5cb4022b02709b");
    byte[] aad = TestUtil.hexDecode(""
        + "f33388860000000000004e91");
    DjbCipherPoly1305 aead = DjbCipherPoly1305.constructChaCha20Poly1305(key);
    Truth.assertThat(aead.decrypt(ciphertext, aad)).isEqualTo(TestUtil.hexDecode(""
        + "496e7465726e65742d44726166747320"
        + "61726520647261667420646f63756d65"
        + "6e74732076616c696420666f72206120"
        + "6d6178696d756d206f6620736978206d"
        + "6f6e74687320616e64206d6179206265"
        + "20757064617465642c207265706c6163"
        + "65642c206f72206f62736f6c65746564"
        + "206279206f7468657220646f63756d65"
        + "6e747320617420616e792074696d652e"
        + "20497420697320696e617070726f7072"
        + "6961746520746f2075736520496e7465"
        + "726e65742d4472616674732061732072"
        + "65666572656e6365206d617465726961"
        + "6c206f7220746f206369746520746865"
        + "6d206f74686572207468616e20617320"
        + "2fe2809c776f726b20696e2070726f67"
        + "726573732e2fe2809d"));
  }

  @Test
  public void testRandomChaCha20Poly1305() throws GeneralSecurityException {
    for (int i = 0; i < 1000; i++) {
      byte[] expectedInput = Random.randBytes(new java.util.Random().nextInt(300));
      byte[] aad = Random.randBytes(DjbCipherPoly1305.BLOCK_SIZE_IN_BYTES);
      byte[] key = Random.randBytes(32);
      DjbCipherPoly1305 cipher = DjbCipherPoly1305.constructChaCha20Poly1305(key);
      byte[] output = cipher.encrypt(expectedInput, aad);
      byte[] nonce = Arrays.copyOfRange(
          output, DjbCipherPoly1305.BLOCK_SIZE_IN_BYTES,
          ChaCha20.NONCE_SIZE_IN_BYTES + DjbCipherPoly1305.BLOCK_SIZE_IN_BYTES);
      byte[] actualInput = null;
      try {
        actualInput = cipher.decrypt(output, aad);
        assertTrue(Arrays.equals(expectedInput, actualInput));
      } catch (Exception e) {
        String error = String.format(
            "\n\nIteration: %d\nMessage: %s\nAad: %s\nKey: %s\nNonce: %s\nOutput: %s\n"
                + "Decrypted Msg: %s\n",
            i,
            TestUtil.hexEncode(expectedInput),
            TestUtil.hexEncode(aad),
            TestUtil.hexEncode(key),
            TestUtil.hexEncode(nonce),
            TestUtil.hexEncode(output),
            actualInput == null ? "null" : TestUtil.hexEncode(actualInput));
        fail(error);
      }
    }
  }

  @Test
  public void testEncryptingEmptyString() throws GeneralSecurityException {
    byte[] aad = Random.randBytes(DjbCipherPoly1305.BLOCK_SIZE_IN_BYTES);
    byte[] key = Random.randBytes(32);
    DjbCipherPoly1305 cipher = DjbCipherPoly1305.constructChaCha20Poly1305(key);
    byte[] ciphertext = cipher.encrypt(new byte[0], aad);
    Truth.assertThat(cipher.decrypt(ciphertext, aad)).isEqualTo(new byte[0]);
  }

  @Test
  public void testChaChaPoly1305ThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() {
    try {
      DjbCipherPoly1305.constructChaCha20Poly1305(new byte[33]);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testChaChaPoly1305ThrowsIllegalArgExpWhenKeyLenIsLessThan32() {
    try {
      DjbCipherPoly1305.constructChaCha20Poly1305(new byte[31]);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testChaCha20DecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort() {
    DjbCipherPoly1305 cipher = DjbCipherPoly1305.constructChaCha20Poly1305(new byte[32]);
    try {
      cipher.decrypt(new byte[27], new byte[1]);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      Truth.assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
    }
  }
}
