// Copyright 2021 Google LLC
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

import static com.google.crypto.tink.aead.internal.Poly1305.MAC_KEY_SIZE_IN_BYTES;
import static com.google.crypto.tink.aead.internal.Poly1305.MAC_TAG_SIZE_IN_BYTES;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.common.truth.Truth;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Poly1305}.
 */
@RunWith(JUnit4.class)
public class Poly1305Test {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @Test
  public void testPoly1305ComputeMacThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> Poly1305.computeMac(new byte[MAC_KEY_SIZE_IN_BYTES + 1], new byte[0]));
    Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testPoly1305ComputeMacThrowsIllegalArgExpWhenKeyLenIsLessThan32() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> Poly1305.computeMac(new byte[MAC_KEY_SIZE_IN_BYTES - 1], new byte[0]));
    Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testPoly1305VerifyMacThrowsIllegalArgExpWhenKeyLenIsGreaterThan32()
      throws GeneralSecurityException {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                Poly1305.verifyMac(new byte[MAC_KEY_SIZE_IN_BYTES + 1], new byte[0], new byte[0]));
    Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testPoly1305VerifyMacThrowsIllegalArgExpWhenKeyLenIsLessThan32()
      throws GeneralSecurityException {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                Poly1305.verifyMac(new byte[MAC_KEY_SIZE_IN_BYTES - 1], new byte[0], new byte[0]));
    Truth.assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
  }

  @Test
  public void testRandomPoly1305Mac() throws GeneralSecurityException {
    for (int i = 0; i < 1000; i++) {
      byte[] in = Random.randBytes(new java.util.Random().nextInt(300));
      byte[] key = Random.randBytes(MAC_KEY_SIZE_IN_BYTES);
      byte[] mac = Poly1305.computeMac(key, in);
      try {
        Poly1305.verifyMac(key, in, mac);
      } catch (Throwable e) {
        String error = String.format(
            "\n\nIteration: %d\nInput: %s\nKey: %s\nMac: %s\n",
            i,
            TestUtil.hexEncode(in),
            TestUtil.hexEncode(key),
            TestUtil.hexEncode(mac));
        fail(error + e.getMessage());
      }
    }
  }

  @Test
  public void testFailedVerification() throws GeneralSecurityException {
    byte[] key = new byte[MAC_KEY_SIZE_IN_BYTES];
    key[0] = 1;
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Poly1305.verifyMac(key, new byte[] {1}, new byte[MAC_TAG_SIZE_IN_BYTES]));
    Truth.assertThat(e).hasMessageThat().containsMatch("invalid MAC");
  }

  /**
   * Tests against the test vectors in Section 2.5.2 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#section-2.5.2
   */
  @Test
  public void testPoly1305() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "85d6be7857556d337f4452fe42d506a8"
        + "0103808afb0db2fd4abff6af4149f51b");
    byte[] in = ("Cryptographic Forum Research Group").getBytes(UTF_8);
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "a8061dc1305136c6c22b8baf0c0127a9"));
  }

  /**
   * Tests against the test vector 1 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector1() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000"
        + "00000000000000000000000000000000");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "00000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 2 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector2() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "00000000000000000000000000000000"
        + "36e5f6b5c5e06070f0efca96227a863e");
    byte[] in = (
        "Any submission to the IETF intended by the Contributor for publication as all or "
            + "part of an IETF Internet-Draft or RFC and any statement made within the context "
            + "of an IETF activity is considered an \"IETF Contribution\". Such statements "
            + "include oral statements in IETF sessions, as well as written and electronic "
            + "communications made at any time or place, which are addressed to")
        .getBytes(UTF_8);
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "36e5f6b5c5e06070f0efca96227a863e"));
  }

  /**
   * Tests against the test vector 3 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector3() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "36e5f6b5c5e06070f0efca96227a863e"
        + "00000000000000000000000000000000");
    byte[] in = (
        "Any submission to the IETF intended by the Contributor for publication as all or "
            + "part of an IETF Internet-Draft or RFC and any statement made within the context "
            + "of an IETF activity is considered an \"IETF Contribution\". Such statements "
            + "include oral statements in IETF sessions, as well as written and electronic "
            + "communications made at any time or place, which are addressed to")
        .getBytes(UTF_8);
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "f3477e7cd95417af89a6b8794c310cf0"));
  }

  /**
   * Tests against the test vector 4 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector4() throws GeneralSecurityException {
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
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "4541669a7eaaee61e708dc7cbcc5eb62"));
  }

  /**
   * Tests against the test vector 5 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector5() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "02000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "ffffffffffffffffffffffffffffffff");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "03000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 6 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector6() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "02000000000000000000000000000000"
        + "ffffffffffffffffffffffffffffffff");
    byte[] in = TestUtil.hexDecode(""
        + "02000000000000000000000000000000");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "03000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 7 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector7() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "ffffffffffffffffffffffffffffffff"
        + "f0ffffffffffffffffffffffffffffff"
        + "11000000000000000000000000000000");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "05000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 8 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector8() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "ffffffffffffffffffffffffffffffff"
        + "fbfefefefefefefefefefefefefefefe"
        + "01010101010101010101010101010101");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "00000000000000000000000000000000"));
  }

  /**
   * Tests against the test vector 9 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector9() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "02000000000000000000000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "fdffffffffffffffffffffffffffffff");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "faffffffffffffffffffffffffffffff"));
  }

  /**
   * Tests against the test vector 10 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector10() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000400000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "e33594d7505e43b90000000000000000"
        + "3394d7505e4379cd0100000000000000"
        + "00000000000000000000000000000000"
        + "01000000000000000000000000000000");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "14000000000000005500000000000000"));
  }

  /**
   * Tests against the test vector 11 in Appendix A.3 of RFC 7539.
   * https://tools.ietf.org/html/rfc7539#appendix-A.3
   */
  @Test
  public void testPoly1305TestVector11() throws GeneralSecurityException {
    byte[] key = TestUtil.hexDecode(""
        + "01000000000000000400000000000000"
        + "00000000000000000000000000000000");
    byte[] in = TestUtil.hexDecode(""
        + "e33594d7505e43b90000000000000000"
        + "3394d7505e4379cd0100000000000000"
        + "00000000000000000000000000000000");
    Truth.assertThat(Poly1305.computeMac(key, in)).isEqualTo(TestUtil.hexDecode(""
        + "13000000000000000000000000000000"));
  }
}
