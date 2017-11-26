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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import com.google.common.truth.Truth;
import com.google.crypto.tink.TestUtil;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link XSalsa20} */
@RunWith(JUnit4.class)
public class XSalsa20Test {
  public Snuffle createInstance(byte[] key) throws InvalidKeyException {
    return new XSalsa20(
        key, 0
        /** initial counter */
        );
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    for (int i = 0; i < 64; i++) {
      byte[] key = Random.randBytes(32);
      IndCpaCipher cipher = createInstance(key);
      for (int j = 0; j < 64; j++) {
        byte[] expectedInput = Random.randBytes(new java.util.Random().nextInt(300));
        byte[] output = cipher.encrypt(expectedInput);
        byte[] actualInput = cipher.decrypt(output);
        assertArrayEquals(
            String.format(
                "\n\nMessage: %s\nKey: %s\nOutput: %s\nDecrypted Msg: %s\n",
                TestUtil.hexEncode(expectedInput),
                TestUtil.hexEncode(key),
                TestUtil.hexEncode(output),
                TestUtil.hexEncode(actualInput)),
            expectedInput,
            actualInput);
      }
    }
  }

  @Test
  public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsLessThan32() throws Exception {
    try {
      createInstance(new byte[1]);
      fail("Expected InvalidKeyException.");
    } catch (InvalidKeyException e) {
      assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() throws Exception {
    try {
      createInstance(new byte[33]);
      fail("Expected InvalidKeyException.");
    } catch (InvalidKeyException e) {
      assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
    }
  }

  @Test
  public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort() throws Exception {
    try {
      IndCpaCipher cipher = createInstance(Random.randBytes(32));
      cipher.decrypt(new byte[2]);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
    }
  }

  private static void testQuarterRound(long[] in, long[] output) {
    int[] x = TestUtil.twoCompInt(in);
    XSalsa20.quarterRound(x, 0, 1, 2, 3);
    Truth.assertThat(x).isEqualTo(TestUtil.twoCompInt(output));
  }

  private static void testRowRound(long[] in, long[] output) {
    int[] x = TestUtil.twoCompInt(in);
    XSalsa20.rowRound(x);
    Truth.assertThat(x).isEqualTo(TestUtil.twoCompInt(output));
  }

  private static void testColumnRound(long[] in, long[] output) {
    int[] x = TestUtil.twoCompInt(in);
    XSalsa20.columnRound(x);
    Truth.assertThat(x).isEqualTo(TestUtil.twoCompInt(output));
  }

  private static void testDoubleRound(long[] in, long[] output) {
    int[] x = TestUtil.twoCompInt(in);
    XSalsa20.columnRound(x);
    XSalsa20.rowRound(x);
    Truth.assertThat(x).isEqualTo(TestUtil.twoCompInt(output));
  }

  /** Section 3 http://cr.yp.to/snuffle/spec.pdf */
  @Test
  public void testQuarterRounds() {
    testQuarterRound(new long[4], new long[4]);
    testQuarterRound(
        new long[] {0x00000001, 0x00000000, 0x00000000, 0x00000000},
        new long[] {0x08008145, 0x00000080, 0x00010200, 0x20500000});
    testQuarterRound(
        new long[] {0x00000000, 0x00000001, 0x00000000, 0x00000000},
        new long[] {0x88000100, 0x00000001, 0x00000200, 0x00402000});
    testQuarterRound(
        new long[] {0x00000000, 0x00000000, 0x00000001, 0x00000000},
        new long[] {0x80040000, 0x00000000, 0x00000001, 0x00002000});
    testQuarterRound(
        new long[] {0x00000000, 0x00000000, 0x00000000, 0x00000001},
        new long[] {0x00048044, 0x00000080, 0x00010000, 0x20100001});
    testQuarterRound(
        new long[] {0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137},
        new long[] {0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3});
    testQuarterRound(
        new long[] {0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b},
        new long[] {0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c});
  }

  /** Section 4 http://cr.yp.to/snuffle/spec.pdf */
  @Test
  public void testRowRounds() {
    testRowRound(
        new long[] {
          0x00000001, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000
        },
        new long[] {
          0x08008145, 0x00000080, 0x00010200, 0x20500000,
          0x20100001, 0x00048044, 0x00000080, 0x00010000,
          0x00000001, 0x00002000, 0x80040000, 0x00000000,
          0x00000001, 0x00000200, 0x00402000, 0x88000100
        });
    testRowRound(
        new long[] {
          0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
          0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
          0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
          0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
        },
        new long[] {
          0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
          0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
          0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
          0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d
        });
  }

  /** Section 5 http://cr.yp.to/snuffle/spec.pdf */
  @Test
  public void testColumnRounds() {
    testColumnRound(
        new long[] {
          0x00000001, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000
        },
        new long[] {
          0x10090288, 0x00000000, 0x00000000, 0x00000000,
          0x00000101, 0x00000000, 0x00000000, 0x00000000,
          0x00020401, 0x00000000, 0x00000000, 0x00000000,
          0x40a04001, 0x00000000, 0x00000000, 0x00000000
        });
    testColumnRound(
        new long[] {
          0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
          0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
          0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
          0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
        },
        new long[] {
          0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
          0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
          0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
          0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8
        });
  }

  /** Section 6 http://cr.yp.to/snuffle/spec.pdf */
  @Test
  public void testDoubleRounds() {
    testDoubleRound(
        new long[] {
          0x00000001, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000
        },
        new long[] {
          0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
          0x08000090, 0x02402200, 0x00004000, 0x00800000,
          0x00010200, 0x20400000, 0x08008104, 0x00000000,
          0x20500000, 0xa0000040, 0x0008180a, 0x612a8020
        });
    testDoubleRound(
        new long[] {
          0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
          0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
          0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
          0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1
        },
        new long[] {
          0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
          0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
          0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
          0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277
        });
  }

  private static class HSalsa20TestVector {
    public byte[] key;
    public byte[] nonce;
    public byte[] out;

    public HSalsa20TestVector(String key, String nonce, String out) {
      this.key = Hex.decode(key);
      this.nonce = Hex.decode(nonce);
      this.out = Hex.decode(out);
    }
  }

  // Copied from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf.
  private static HSalsa20TestVector[] hSalsa20TestVectors = {
    new HSalsa20TestVector(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        "00000000000000000000000000000000",
        "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"),
    new HSalsa20TestVector(
        "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389",
        "69696ee955b62b73cd62bda875fc73d6",
        "dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4"),
  };

  /** See example 1, section 8, http://cr.yp.to/highspeed/naclcrypto-20090310.pdf */
  @Test
  public void testHSalsa20WithNaClBoxTestVectors() {
    for (HSalsa20TestVector test : hSalsa20TestVectors) {
      byte[] output = XSalsa20.hSalsa20(test.key, test.nonce);
      Truth.assertThat(output).isEqualTo(test.out);
    }
  }

  /** See example 2, section 8, http://cr.yp.to/highspeed/naclcrypto-20090310.pdf */
  @Test
  public void testKeyStreamNaClBoxTestVectors() throws Exception {
    byte[] key = Hex.decode("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
    Snuffle cipher =
        new XSalsa20(
            key, 0
            /** initial counter */
            );
    byte[] nonce = Hex.decode("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
    ByteBuffer out = ByteBuffer.allocate(65536 * 64).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < 65536; i++) {
      out.put(cipher.getKeyStreamBlock(nonce, i));
    }
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    Truth.assertThat(digest.digest(out.array()))
        .isEqualTo(Hex.decode("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2"));
  }

  /** Test vectors copied from section 10, http://cr.yp.to/highspeed/naclcrypto-20090310.pdf */
  @Test
  public void testEncryptDecryptWithNaClBoxTestVectors() throws GeneralSecurityException {
    Snuffle cipher =
        createInstance(
            Hex.decode("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"));
    String nonce = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    byte[] ciphertext =
        Hex.decode(
            nonce
                // The first 32-byte of the key stream is the MAC auth key.
                + "0000000000000000000000000000000000000000000000000000000000000000"
                + "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a"
                + "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738"
                + "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da"
                + "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74"
                + "e355a5");
    byte[] output = cipher.decrypt(ciphertext);
    // See "Testing: secretbox vs. onetimeauth", section 10,
    // http://cr.yp.to/highspeed/naclcrypto-20090310.pdf.
    byte[] macKey = Arrays.copyOfRange(output, 0, 32);
    byte[] expectedMacKey =
        Hex.decode("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880");
    Truth.assertThat(macKey).isEqualTo(expectedMacKey);

    // See "Testing: secretbox vs. stream.", section 10,
    // http://cr.yp.to/highspeed/naclcrypto-20090310.pdf.
    byte[] plaintext = Arrays.copyOfRange(output, 32, output.length);
    byte[] expectedPlaintext =
        Hex.decode(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaa"
                + "f33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be825"
                + "0c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb4"
                + "8f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705");
    Truth.assertThat(plaintext).isEqualTo(expectedPlaintext);
  }
}
