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

import static com.google.crypto.tink.subtle.DjbCipher.KEY_SIZE_IN_BYTES;
import static com.google.crypto.tink.subtle.DjbCipherPoly1305.MAC_TAG_SIZE_IN_BYTES;
import static com.google.crypto.tink.subtle.DjbCipherTest.twosCompByte;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.common.truth.Truth;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.subtle.DjbCipher.XSalsa20;
import com.google.crypto.tink.subtle.DjbCipherPoly1305Test.Poly1305Test;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Unit tests for static methods in {@link DjbCipherPoly1305}.
 */
@RunWith(Suite.class)
@SuiteClasses({
    Poly1305Test.class,
    DjbCipherPoly1305Test.ChaCha20Poly1305IetfTest.class,
    DjbCipherPoly1305Test.XSalsa20Poly1305NaclTest.class,
    DjbCipherPoly1305Test.XChaCha20Poly1305NaclTest.class
})
public class DjbCipherPoly1305Test {

  /**
   * Unit tests for {@link DjbCipherPoly1305} static methods.
   */
  public static class Poly1305Test {

    /**
     * Tests against the test vectors in Section 2.5.2 of RFC 7539.
     * https://tools.ietf.org/html/rfc7539#section-2.5.2
     */
    @Test
    public void testPoly1305() {
      byte[] key = TestUtil.hexDecode(""
          + "85d6be7857556d337f4452fe42d506a8"
          + "0103808afb0db2fd4abff6af4149f51b");
      byte[] in = ("Cryptographic Forum Research Group").getBytes(StandardCharsets.US_ASCII);
      byte[] mac = DjbCipherPoly1305.poly1305Mac(in, key);
      Truth.assertThat(mac).isEqualTo(TestUtil.hexDecode(""
          + "a8061dc1305136c6c22b8baf0c0127a9"));
    }

    /**
     * Tests against the test vector 1 in Appendix A.3 of RFC 7539.
     * https://tools.ietf.org/html/rfc7539#appendix-A.3
     */
    @Test
    public void testPoly1305TestVector1() {
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
    public void testPoly1305TestVector2() {
      byte[] key = TestUtil.hexDecode(""
          + "00000000000000000000000000000000"
          + "36e5f6b5c5e06070f0efca96227a863e");
      byte[] in = (
          "Any submission to the IETF intended by the Contributor for publication as all or "
              + "part of an IETF Internet-Draft or RFC and any statement made within the context "
              + "of an IETF activity is considered an \"IETF Contribution\". Such statements "
              + "include oral statements in IETF sessions, as well as written and electronic "
              + "communications made at any time or place, which are addressed to")
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
    public void testPoly1305TestVector3() {
      byte[] key = TestUtil.hexDecode(""
          + "36e5f6b5c5e06070f0efca96227a863e"
          + "00000000000000000000000000000000");
      byte[] in = (
          "Any submission to the IETF intended by the Contributor for publication as all or "
              + "part of an IETF Internet-Draft or RFC and any statement made within the context "
              + "of an IETF activity is considered an \"IETF Contribution\". Such statements "
              + "include oral statements in IETF sessions, as well as written and electronic "
              + "communications made at any time or place, which are addressed to")
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
    public void testPoly1305TestVector4() {
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
    public void testPoly1305TestVector5() {
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
    public void testPoly1305TestVector6() {
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
    public void testPoly1305TestVector7() {
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
    public void testPoly1305TestVector8() {
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
    public void testPoly1305TestVector9() {
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
    public void testPoly1305TestVector10() {
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
    public void testPoly1305TestVector11() {
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
  }

  /**
   * Unit test base class for DjbCipherPoly1305.
   */
  abstract static class Poly1305TestBase {

    protected abstract DjbCipherPoly1305 createInstance(byte[] key);

    @Test
    public void testRandomChaCha20Poly1305() throws GeneralSecurityException {
      for (int i = 0; i < 1000; i++) {
        byte[] expectedInput = Random.randBytes(new java.util.Random().nextInt(300));
        byte[] aad = Random.randBytes(MAC_TAG_SIZE_IN_BYTES);
        byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
        DjbCipherPoly1305 cipher = createInstance(key);
        byte[] output = cipher.encrypt(expectedInput, aad);
        byte[] nonce = Arrays.copyOfRange(
            output, MAC_TAG_SIZE_IN_BYTES,
            cipher.nonceSizeInBytes() + MAC_TAG_SIZE_IN_BYTES);
        byte[] actualInput = null;
        try {
          actualInput = cipher.decrypt(output, aad);
          assertTrue(Arrays.equals(expectedInput, actualInput));
        } catch (Throwable e) {
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
      byte[] aad = Random.randBytes(MAC_TAG_SIZE_IN_BYTES);
      byte[] key = Random.randBytes(KEY_SIZE_IN_BYTES);
      DjbCipherPoly1305 cipher = createInstance(key);
      byte[] ciphertext = cipher.encrypt(new byte[0], aad);
      Truth.assertThat(cipher.decrypt(ciphertext, aad)).isEqualTo(new byte[0]);
    }

    @Test
    public void testPoly1305ThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() {
      try {
        createInstance(new byte[KEY_SIZE_IN_BYTES + 1]);
        fail("Expected IllegalArgumentException.");
      } catch (IllegalArgumentException e) {
        Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
      }
    }

    @Test
    public void testPoly1305ThrowsIllegalArgExpWhenKeyLenIsLessThan32() {
      try {
        createInstance(new byte[KEY_SIZE_IN_BYTES - 1]);
        fail("Expected IllegalArgumentException.");
      } catch (IllegalArgumentException e) {
        Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
      }
    }

    @Test
    public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort() {
      DjbCipherPoly1305 cipher = createInstance(new byte[KEY_SIZE_IN_BYTES]);
      try {
        cipher.decrypt(new byte[27], new byte[1]);
        fail("Expected GeneralSecurityException.");
      } catch (GeneralSecurityException e) {
        Truth.assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
      }
    }
  }

  /**
   * Unit test base class for ChaCha20Poly1305.
   */
  public static class ChaCha20Poly1305IetfTest extends Poly1305TestBase {

    @Override
    protected DjbCipherPoly1305 createInstance(byte[] key) {
      return DjbCipherPoly1305.constructChaCha20Poly1305Ietf(key);
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
      DjbCipher cipher = DjbCipher.chaCha20(key);
      Truth.assertThat(cipher.getAuthenticatorKey(nonce)).isEqualTo(TestUtil.hexDecode(""
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
          + "070000004041424344454647"          // nonce
          + "d31a8d34648e60db7b86afbc53ef7ec2"  // ciphertext
          + "a4aded51296e08fea9e2b5a736ee62d6"
          + "3dbea45e8ca9671282fafb69da92728b"
          + "1a71de0a9e060b2905d6a5b67ecd3b36"
          + "92ddbd7f2d778b8c9803aee328091b58"
          + "fab324e4fad675945585808b4831d7bc"
          + "3ff4def08e4b7a9de576d26586cec64b"
          + "6116"
          + "1ae10b594f09e26a7e902ecbd0600691"  // tag
      );
      byte[] aad = TestUtil.hexDecode("50515253c0c1c2c3c4c5c6c7");
      DjbCipherPoly1305 aead = createInstance(key);
      Truth.assertThat(aead.decrypt(ciphertext, aad)).isEqualTo(
          ("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
              + "future, sunscreen would be it.").getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    public void testDecryptThrowsGeneralSecExpForCorruptInput() throws GeneralSecurityException {
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
        createInstance(key).decrypt(ciphertext, aad);
        fail("Expected GeneralSecurityException.");
      } catch (GeneralSecurityException e) {
        Truth.assertThat(e).hasMessageThat().containsMatch("Tags do not match.");
      }

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
      DjbCipher cipher = DjbCipher.chaCha20(key);
      Truth.assertThat(cipher.getAuthenticatorKey(nonce)).isEqualTo(TestUtil.hexDecode(""
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
      DjbCipher cipher = DjbCipher.chaCha20(key);
      Truth.assertThat(cipher.getAuthenticatorKey(nonce)).isEqualTo(TestUtil.hexDecode(""
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
      DjbCipher cipher = DjbCipher.chaCha20(key);
      Truth.assertThat(cipher.getAuthenticatorKey(nonce)).isEqualTo(TestUtil.hexDecode(""
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
          + "a6ad5cb4022b02709b"
          + "eead9d67890cbb22392336fea1851f38"  // tag
      );
      byte[] aad = TestUtil.hexDecode(""
          + "f33388860000000000004e91");
      DjbCipherPoly1305 aead = createInstance(key);
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
  }

  /**
   * Unit test base class for XSalsa20Poly1305.
   */
  public static class XSalsa20Poly1305NaclTest extends Poly1305TestBase {

    @Override
    protected DjbCipherPoly1305 createInstance(byte[] key) {
      return DjbCipherPoly1305.constructXSalsa20Poly1305Nacl(key);
    }

    private static byte[] sharedKey(byte[] privateKey, byte[] publicKey) {
      return Curve25519.x25519(privateKey, publicKey);
    }

    /**
     * Section 10, Example 1 in decrypt mode
     * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void testXSalsa20Poly1305Decrypt() throws GeneralSecurityException {
      byte[] sharedKey = sharedKey(twosCompByte(new int[]{
              0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
              0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
              0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
              0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a}),
          twosCompByte(new int[]{
              0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
              0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
              0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
              0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f}));
      DjbCipherPoly1305 cipher = createInstance(XSalsa20.hSalsa20(sharedKey));
      byte[] plaintext = cipher.decrypt(twosCompByte(new int[]{
          0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
          0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
          0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
          0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
          0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
          0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
          0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
          0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
          0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
          0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
          0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
          0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
          0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
          0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
          0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
          0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
          0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
          0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
          0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
          0xe3, 0x55, 0xa5,
          0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
          0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9}), null);
      Truth.assertThat(plaintext).isEqualTo(twosCompByte(new int[]{
          0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
          0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
          0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
          0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
          0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
          0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
          0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
          0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
          0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
          0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
          0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
          0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
          0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
          0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
          0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
          0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
          0x5e, 0x07, 0x05}));
    }
  }

  /**
   * Unit test base class for XChaCha20Poly1305.
   */
  public static class XChaCha20Poly1305NaclTest extends Poly1305TestBase {

    // From libsodium's test/default/xchacha20.c (tv_secretbox_xchacha20poly1305)
    private static String[][] xChaCha20Poly1305Tvs = {
        {"065ff46a9dddb1ab047ee5914d6d575a828b8cc1f454b24e8cd0f57efdc49a34",
            "f83262646ce01293b9923a65a073df78c54b2e799cd6c4e5", "",
            "4c72340416339dcdea01b760db5adaf7"},
        {"d3c71d54e6b13506e07aa2e7b412a17a7a1f34df3d3148cd3f45b91ccaa5f4d9",
            "943b454a853aa514c63cf99b1e197bbb99da24b2e2d93e47",
            "76bd706e07741e713d90efdb34ad202067263f984942aae8bda159f30dfccc72200f8093520b85c5ad124f"
                + "f7c8b2d920946e5cfff4b819abf84c7b35a6205ca72c9f8747c3044dd73fb4bebda1b476",
            "0384276f1cfa5c82c3e58f0f2acc1f821c6f526d2c19557cf8bd270fcde43fba1d88890663f7b2f5c6b1d7"
                + "deccf5c91b4df5865dc55cc7e04d6793fc2db8f9e3b418f95cb796d67a7f3f7e097150cb607c435d"
                + "acf82eac3d669866e5092ace"},
        {"9498fdb922e0596e32af7f8108def2068f5a32a5ac70bd33ade371701f3d98d0",
            "a0056f24be0d20106fe750e2ee3684d4457cbdcb3a74e566",
            "b1bc9cfedb340fb06a37eba80439189e48aa0cfd37020eec0afa09165af12864671b3fbddbbb20ac18f586"
                + "f2f66d13b3ca40c9a7e21c4513a5d87a95319f8ca3c2151e2a1b8b86a35653e77f90b9e63d2a84be"
                + "9b9603876a89d60fd708edcd64b41be1064b8ad1046553aaeb51dc70b8112c9915d94f2a5dad1e14"
                + "e7009db6c703c843a4f64b77d44b179b9579ac497dac2d33",
            "4918790d46893fa3dca74d8abc57eef7fca2c6393d1beef5efa845ac20475db38d1a068debf4c5dbd8614e"
                + "b072877c565dc52bd40941f0b590d2079a5028e426bf50bcbaadcbebf278bddceedc578a5e313795"
                + "23dee15026ec82d34e56f2871fdf13255db199ac48f163d5ee7e4f4e09a39451356959d9242a39ae"
                + "a33990ab960a4c25346e3d9397fc5e7cb6266c2476411cd331f2bcb4486750c746947ec6401865d5"
        },
        {"fa2d915e044d0519248150e7c815b01f0f2a691c626f8d22c3ef61e7f16eea47",
            "c946065dc8befa9cc9f292ea2cf28f0256285565051792b7",
            "d5be1a24c7872115dc5c5b4234dbee35a6f89ae3a91b3e33d75249a0aecfed252341295f49296f7ee14d64"
                + "de1ea6355cb8facd065052d869aeb1763cda7e418a7e33b6f7a81327181df6cd4de3a126d9df1b5e"
                + "8b0b1a6b281e63f2",
            "6d32e3571afec58b0acabb54a287118b3ed6691f56cc8ead12d735352c9a050c2ca173c78b6092f9ad4b7c"
                + "21c36fb0ce18560956395bab3099c54760a743051ac6a898a0b0034b5e953340c975cf7a873c56b2"
                + "7e66bca2bff1dd977addefc7935bb7550753dd13d1f1a43d"},
        {"6f149c2ec27af45176030c8dd7ab0e1e488f5803f26f75045d7a56f59a587a85",
            "952aff2f39bc70016f04ac7fb8b55fd22764ba16b56e255d",
            "8fde598c4bde5786abdc6ab83fce66d59782b6ce36afe028c447ad4086a748764afa88a520e837a9d56d0b"
                + "7693b0476649f24c2aa44b94615a1efc75",
            "9bccf07974836fa4609d32d9527d928d184d9c6c0823af2f703e0e257a162d26d3678fa15ab1c4db76ac42"
                + "084d32cefca8efaf77814c199b310999e327a3e3daa2e235b175979504ede87b58"},
        {"b964b7fdf442efbcc2cd3e4cd596035bdfb05ed7d44f7fd4dce2d5614af5c8c4",
            "2886fbfa4b35b68f28d31df6243a4fbc56475b69e24820a4", "",
            "b83fbdd112bf0f7d62eff96c9faa8850"},
        {"10c0ad4054b48d7d1de1d9ab6f782ca883d886573e9d18c1d47b6ee6b5208189",
            "977edf57428d0e0247a3c88c9a9ec321bbaae1a4da8353b5",
            "518e4a27949812424b2a381c3efea6055ee5e75eff",
            "0c801a037c2ed0500d6ef68e8d195eceb05a15f8edb68b35773e81ac2aca18e9be53416f9a"},
        {"7db0a81d01699c86f47a3ec76d46aa32660adad7f9ac72cf8396419f789f6bb1",
            "e7cb57132ce954e28f4470cca1dbda20b534cdf32fbe3658",
            "ee6511d403539e611ab312205f0c3b8f36a33d36f1dc44bb33d6836f0ab93b9f1747167bf0150f045fcd12"
                + "a39479641d8bdde6fe01475196e8fe2c435e834e30a59f6aaa01ebcd",
            "ae8b1d4df4f982b2702626feca07590fedd0dfa7ae34e6a098372a1aa32f9fbf0ce2a88b5c16a571ef48f3"
                + "c9fda689ce8ebb9947c9e2a28e01b1191efc81ad2ce0ed6e6fc7c164b1fc7f3d50b7f5e47a895db3"
                + "c1fc46c0"},
        {"7b043dd27476cf5a2baf2907541d8241ecd8b97d38d08911737e69b0846732fb",
            "74706a2855f946ed600e9b453c1ac372520b6a76a3c48a76",
            "dbf165bb8352d6823991b99f3981ba9c8153635e5695477cba54e96a2a8c4dc5f9dbe817887d7340e3f4"
                + "8a",
            "ce57261afba90a9598de15481c43f26f7b8c8cb2806c7c977752dba898dc51b92a3f1a62ebf696747bfccf"
                + "72e0edda97f2ccd6d496f55aefbb3ec2"},
        {"e588e418d658df1b2b1583122e26f74ca3506b425087bea895d81021168f8164",
            "4f4d0ffd699268cd841ce4f603fe0cd27b8069fcf8215fbb",
            "f91bcdcf4d08ba8598407ba8ef661e66c59ca9d89f3c0a3542e47246c777091e4864e63e1e3911dc012572"
                + "55e551527a53a34481be",
            "22dc88de7cacd4d9ce73359f7d6e16e74caeaa7b0d1ef2bb10fda4e79c3d5a9aa04b8b03575fd27bc970c9"
                + "ed0dc80346162469e0547030ddccb8cdc95981400907c87c9442"}
    };

    @Override
    protected DjbCipherPoly1305 createInstance(byte[] key) {
      return DjbCipherPoly1305.constructXChaCha20Poly1305Nacl(key);
    }

    @Test
    public void testXChaCha20Poly1305Tvs() {
      for (String[] tv : xChaCha20Poly1305Tvs) {
        DjbCipherPoly1305 cipher = DjbCipherPoly1305.constructXChaCha20Poly1305Nacl(
            TestUtil.hexDecode(tv[0]));
        String ciphertext = tv[1] + tv[3].substring(2 * MAC_TAG_SIZE_IN_BYTES)
            + tv[3].substring(0, 2 * MAC_TAG_SIZE_IN_BYTES);
        try {
          Truth.assertThat(TestUtil.hexEncode(cipher.decrypt(TestUtil.hexDecode(ciphertext), null)))
              .isEqualTo(tv[2]);
        } catch (GeneralSecurityException e) {
          fail(e.getMessage() + " caused by following test vector:\n" + Arrays.toString(tv));
        }
      }
    }
  }
}
