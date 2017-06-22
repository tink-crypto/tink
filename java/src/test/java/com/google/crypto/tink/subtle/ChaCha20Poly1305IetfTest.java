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

import static org.junit.Assert.fail;

import com.google.common.truth.Truth;
import com.google.crypto.tink.TestUtil;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit test base class for ChaCha20Poly1305.
 */
@RunWith(JUnit4.class)
public class ChaCha20Poly1305IetfTest extends DjbCipherPoly1305TestBase {

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
    ChaCha20 cipher = new ChaCha20(key);
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
    DjbCipherPoly1305 aead = createInstance(key);
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
    ChaCha20 cipher = new ChaCha20(key);
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
    ChaCha20 cipher = new ChaCha20(key);
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
    ChaCha20 cipher = new ChaCha20(key);
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
