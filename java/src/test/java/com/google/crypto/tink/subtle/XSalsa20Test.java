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

import com.google.common.truth.Truth;
import com.google.crypto.tink.TestUtil;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for XSalsa20.
 */
@RunWith(JUnit4.class)
public class XSalsa20Test extends DJBCipherTestBase<XSalsa20> {

  private static final XSalsa20 dummy = new XSalsa20(new byte[32]);

  @Override
  protected XSalsa20 createInstance(byte[] key) {
    return new XSalsa20(key);
  }

  private static int[] matrix(int[] bytes) {
    return DJBCipher.toIntArray(
        ByteBuffer.wrap(twosCompByte(bytes)).order(ByteOrder.LITTLE_ENDIAN));
  }

  private static void testQuarterRound(long[] in, long[] output) {
    int[] x = twosCompInt(in);
    XSalsa20.quarterRound(x, 0, 1, 2, 3);
    Truth.assertThat(x).isEqualTo(twosCompInt(output));
  }

  private static void testRowRound(long[] in, long[] output) {
    int[] x = twosCompInt(in);
    XSalsa20.rowRound(x);
    Truth.assertThat(x).isEqualTo(twosCompInt(output));
  }

  private static void testColumnRound(long[] in, long[] output) {
    int[] x = twosCompInt(in);
    XSalsa20.columnRound(x);
    Truth.assertThat(x).isEqualTo(twosCompInt(output));
  }

  private static void testDoubleRound(long[] in, long[] output) {
    int[] x = twosCompInt(in);
    XSalsa20.columnRound(x);
    XSalsa20.rowRound(x);
    Truth.assertThat(x).isEqualTo(twosCompInt(output));
  }

  private static void testSalsa20(int[] in, int[] output, int count) {
    int[] x = matrix(in);
    ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < count; i++) {
      buf.asIntBuffer().put(dummy.shuffleAdd(x));
      x = DJBCipher.toIntArray(buf);
    }
    Truth.assertThat(buf.array()).isEqualTo(twosCompByte(output));
  }

  /**
   * Section 3
   * http://cr.yp.to/snuffle/spec.pdf
   */
  @Test
  public void testQuarterRounds() {
    testQuarterRound(new long[4], new long[4]);
    testQuarterRound(
        new long[]{0x00000001, 0x00000000, 0x00000000, 0x00000000},
        new long[]{0x08008145, 0x00000080, 0x00010200, 0x20500000});
    testQuarterRound(
        new long[]{0x00000000, 0x00000001, 0x00000000, 0x00000000},
        new long[]{0x88000100, 0x00000001, 0x00000200, 0x00402000});
    testQuarterRound(
        new long[]{0x00000000, 0x00000000, 0x00000001, 0x00000000},
        new long[]{0x80040000, 0x00000000, 0x00000001, 0x00002000});
    testQuarterRound(
        new long[]{0x00000000, 0x00000000, 0x00000000, 0x00000001},
        new long[]{0x00048044, 0x00000080, 0x00010000, 0x20100001});
    testQuarterRound(
        new long[]{0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137},
        new long[]{0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3});
    testQuarterRound(
        new long[]{0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b},
        new long[]{0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c});
  }

  /**
   * Section 4
   * http://cr.yp.to/snuffle/spec.pdf
   */
  @Test
  public void testRowRounds() {
    testRowRound(
        new long[]{
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000},
        new long[]{
            0x08008145, 0x00000080, 0x00010200, 0x20500000,
            0x20100001, 0x00048044, 0x00000080, 0x00010000,
            0x00000001, 0x00002000, 0x80040000, 0x00000000,
            0x00000001, 0x00000200, 0x00402000, 0x88000100});
    testRowRound(
        new long[]{
            0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
            0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
            0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
            0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a},
        new long[]{
            0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
            0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
            0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
            0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d});
  }

  /**
   * Section 5
   * http://cr.yp.to/snuffle/spec.pdf
   */
  @Test
  public void testColumnRounds() {
    testColumnRound(
        new long[]{
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000001, 0x00000000, 0x00000000, 0x00000000},
        new long[]{
            0x10090288, 0x00000000, 0x00000000, 0x00000000,
            0x00000101, 0x00000000, 0x00000000, 0x00000000,
            0x00020401, 0x00000000, 0x00000000, 0x00000000,
            0x40a04001, 0x00000000, 0x00000000, 0x00000000});
    testColumnRound(
        new long[]{
            0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
            0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
            0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
            0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a},
        new long[]{
            0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
            0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
            0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
            0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8});
  }

  /**
   * Section 6
   * http://cr.yp.to/snuffle/spec.pdf
   */
  @Test
  public void testDoubleRounds() {
    testDoubleRound(
        new long[]{
            0x00000001, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000},
        new long[]{
            0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
            0x08000090, 0x02402200, 0x00004000, 0x00800000,
            0x00010200, 0x20400000, 0x08008104, 0x00000000,
            0x20500000, 0xa0000040, 0x0008180a, 0x612a8020});
    testDoubleRound(
        new long[]{
            0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
            0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
            0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
            0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1},
        new long[]{
            0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
            0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
            0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
            0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277});
  }

  /**
   * Section 8
   * http://cr.yp.to/snuffle/spec.pdf
   */
  @Test
  public void testSalsa20() {
    testSalsa20(
        new int[]{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        1);
    testSalsa20(
        new int[]{
            211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136,
            49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207,
            31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36,
            79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54},
        new int[]{
            109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154,
            29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57,
            118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114,
            219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202},
        1);
    testSalsa20(
        new int[]{
            88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243,
            191, 187, 234, 136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37,
            86, 16, 179, 207, 49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48,
            238, 55, 204, 36, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113},
        new int[]{
            179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158,
            26, 110, 170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203,
            69, 144, 51, 57, 29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48,
            27, 111, 114, 114, 118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35},
        1);
    testSalsa20(
        new int[]{
            6, 124, 83, 146, 38, 191, 9, 50, 4, 161, 47, 222, 122, 182, 223, 185,
            75, 27, 0, 216, 16, 122, 7, 89, 162, 104, 101, 147, 213, 21, 54, 95,
            225, 253, 139, 176, 105, 132, 23, 116, 76, 41, 176, 207, 221, 34, 157, 108,
            94, 94, 99, 52, 90, 117, 91, 220, 146, 190, 239, 143, 196, 176, 130, 186},
        new int[]{
            8, 18, 38, 199, 119, 76, 215, 67, 173, 127, 144, 162, 103, 212, 176, 217,
            192, 19, 233, 33, 159, 197, 154, 160, 128, 243, 219, 65, 171, 136, 135, 225,
            123, 11, 68, 86, 237, 82, 20, 155, 133, 189, 9, 83, 167, 116, 194, 78,
            122, 127, 195, 185, 185, 204, 188, 90, 245, 9, 183, 248, 226, 85, 245, 104},
        1000000);
  }

  /**
   * Testing HSalsa20, example 1
   * Section 8
   * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
   */
  @Test
  public void testHSalsa20_1() {
    XSalsa20 cipher = new XSalsa20(twosCompByte(new int[]{
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42}));
    int[] state = cipher.initialState(new byte[24], 0);
    int[] hSalsa20 = new int[]{
        state[1], state[2], state[3], state[4], state[11], state[12], state[13], state[14]};
    int[] expected = matrix(new int[]{
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89});
    Truth.assertThat(hSalsa20).isEqualTo(expected);
  }

  /**
   * Testing HSalsa20, example 2
   * Section 8
   * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
   */
  @Test
  public void testHSalsa20_2() {
    XSalsa20 cipher = new XSalsa20(twosCompByte(new int[]{
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89}));
    byte[] nonce = twosCompByte(new int[]{
        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    int[] state = cipher.initialState(nonce, 0);
    int[] hSalsa20 = new int[]{
        state[1], state[2], state[3], state[4], state[11], state[12], state[13], state[14]};
    int[] expected = matrix(new int[]{
        0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9,
        0x53, 0x62, 0x9b, 0x73, 0x38, 0x20, 0x77, 0x88,
        0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9,
        0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4});
    Truth.assertThat(hSalsa20).isEqualTo(expected);
  }

  /**
   * Testing HSalsa20, example 2
   * Section 8
   * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
   */
  @Test
  public void testHSalsa20_3() throws NoSuchAlgorithmException {
    XSalsa20 cipher = new XSalsa20(twosCompByte(new int[]{
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89}));
    byte[] nonce = twosCompByte(new int[]{
        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37});
    int[] state = cipher.initialState(nonce, 0);
    ByteBuffer out = ByteBuffer.allocate(4194304).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < 65536; i++) {
      out.asIntBuffer().put(cipher.shuffleAdd(state));
      cipher.incrementCounter(state);
      out.position(out.position() + 64);
    }
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    Truth.assertThat(digest.digest(out.array())).isEqualTo(
        TestUtil.hexDecode("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2"));
  }
}
