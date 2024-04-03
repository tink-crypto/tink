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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.nio.ByteBuffer;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for Bytes */
@RunWith(JUnit4.class)
public class BytesTest {

  // Some test arrays for the XOR operations.
  static final byte[] EMPTY = {};
  static final byte[] ONE_ONE = {1};
  static final byte[] TWO_ONES = {1, 1};
  static final byte[] THREE_ONES = {1, 1, 1};
  static final byte[] THREE_ZEROES = {0, 0, 0};
  static final byte[] TWO_FF = {(byte) 0xFF, (byte) 0xFF};

  @Test
  public void xorTwoArgsBasicTest() {
    byte[] shouldBeZeroes = Bytes.xor(TWO_ONES, TWO_ONES);
    assertEquals(0, shouldBeZeroes[0]);
    assertEquals(0, shouldBeZeroes[1]);
  }

  @Test
  public void xorTwoArgsSizeMismatchA() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(THREE_ZEROES, TWO_ONES));
  }

  @Test
  public void xorTwoArgsSizeMismatchB() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(TWO_ONES, THREE_ZEROES));
  }

  @Test
  public void xorThreeArgsBasicTest() {
    byte[] shouldBeZeroes = Bytes.xor(TWO_ONES, 0, TWO_ONES, 0, 2);
    assertEquals(0, shouldBeZeroes[0]);
    assertEquals(0, shouldBeZeroes[1]);
    assertEquals(2, shouldBeZeroes.length);
  }

  @Test
  public void xorThreeArgsDifferentSizes() {
    byte[] shouldBeOne = Bytes.xor(THREE_ZEROES, 1, TWO_ONES, 0, 1);
    assertEquals(1, shouldBeOne[0]);
    assertEquals(1, shouldBeOne.length);
  }

  @Test
  public void xorThreeArgsTooLong() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(THREE_ZEROES, 0, TWO_ONES, 0, 3));
  }

  @Test
  public void xorThreeArgsTooLongOffsets() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(THREE_ZEROES, 3, TWO_ONES, 1, 1));
  }

  @Test
  public void xorThreeArgsSizeMismatchB() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(TWO_ONES, THREE_ZEROES));
  }

  @Test
  public void xorEndBasicTest() {
    byte[] r = Bytes.xorEnd(THREE_ONES, TWO_FF);
    assertEquals(1, r[0]);
    assertEquals((byte) 0xFE, r[1]);
    assertEquals((byte) 0xFE, r[2]);
    assertEquals(3, r.length);
  }

  @Test
  public void xorEndSizeMismatch() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.xorEnd(TWO_ONES, THREE_ZEROES));
  }

  @Test
  public void xorByteBufferNegativeLength() {
    ByteBuffer output = ByteBuffer.allocate(10);
    ByteBuffer x = ByteBuffer.allocate(10);
    ByteBuffer y = ByteBuffer.allocate(10);
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(output, x, y, -1));
  }

  @Test
  public void xorByteBufferLengthLargerThanOutput() {
    ByteBuffer output = ByteBuffer.allocate(9);
    ByteBuffer x = ByteBuffer.allocate(10);
    ByteBuffer y = ByteBuffer.allocate(10);
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(output, x, y, 10));
  }

  @Test
  public void xorByteBufferLengthLargerThanFirstInput() {
    ByteBuffer output = ByteBuffer.allocate(10);
    ByteBuffer x = ByteBuffer.allocate(9);
    ByteBuffer y = ByteBuffer.allocate(10);
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(output, x, y, 10));
  }

  @Test
  public void xorByteBufferLengthLargerThanSecondInput() {
    ByteBuffer output = ByteBuffer.allocate(10);
    ByteBuffer x = ByteBuffer.allocate(10);
    ByteBuffer y = ByteBuffer.allocate(9);
    assertThrows(IllegalArgumentException.class, () -> Bytes.xor(output, x, y, 10));
  }

  @Test
  public void xorByteBufferBasic() {
    ByteBuffer output = ByteBuffer.allocate(10);
    ByteBuffer x = ByteBuffer.allocate(10);
    ByteBuffer y = ByteBuffer.allocate(10);
    for (int i = 0; i < 10; i++) {
      x.put((byte) i);
      y.put((byte) (i + 1));
    }
    x.flip();
    y.flip();
    Bytes.xor(output, x, y, 10);
    for (int i = 0; i < 10; i++) {
      assertEquals(output.get(i), i ^ (i + 1));
    }
  }

  @Test
  public void intToByteArray_works() {
    assertThat(Bytes.intToByteArray(0, 0)).isEqualTo(new byte[] {});
    assertThat(Bytes.intToByteArray(1, 42)).isEqualTo(new byte[] {(byte) 42});
    assertThat(Bytes.intToByteArray(2, 0x0102)).isEqualTo(new byte[] {(byte) 02, (byte) 0x01});

    assertThat(Bytes.intToByteArray(1, 0xdd)).isEqualTo(new byte[] {(byte) 0xdd});
    assertThat(Bytes.intToByteArray(2, 0xccdd)).isEqualTo(new byte[] {(byte) 0xdd, (byte) 0xcc});
    assertThat(Bytes.intToByteArray(3, 0xbbccdd))
        .isEqualTo(new byte[] {(byte) 0xdd, (byte) 0xcc, (byte) 0xbb});
    assertThat(Bytes.intToByteArray(4, 0x0abbccdd))
        .isEqualTo(new byte[] {(byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0x0a});
    assertThat(Bytes.intToByteArray(4, Integer.MAX_VALUE))
        .isEqualTo(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f});
  }

  @Test
  public void intToByteArray_failsWithInvalidCapacity() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(5, 42));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(-1, 42));
  }

  @Test
  public void intToByteArray_valueTooLong_fails() {
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(0, 1));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(0, -1));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(1, 256));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(1, -1));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(2, 256 * 256));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(2, -1));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(3, 256 * 256 * 256));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(3, -1));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(4, -1));
    assertThrows(IllegalArgumentException.class, () -> Bytes.intToByteArray(4, Integer.MIN_VALUE));
  }

  @Test
  public void intToByteArrayToInt_works() {
    assertThat(Bytes.byteArrayToInt(Bytes.intToByteArray(0, 0))).isEqualTo(0);
    assertThat(Bytes.byteArrayToInt(Bytes.intToByteArray(1, 42))).isEqualTo(42);
    assertThat(Bytes.byteArrayToInt(Bytes.intToByteArray(2, 0x0102))).isEqualTo(0x0102);
    assertThat(Bytes.byteArrayToInt(Bytes.intToByteArray(4, 0x0abbccdd))).isEqualTo(0x0abbccdd);
    assertThat(Bytes.byteArrayToInt(Bytes.intToByteArray(4, Integer.MAX_VALUE)))
        .isEqualTo(Integer.MAX_VALUE);
  }

  @Test
  public void byteArrayToInt_works() {
    assertThat(Bytes.byteArrayToInt(new byte[] {})).isEqualTo(0);
    assertThat(Bytes.byteArrayToInt(new byte[] {(byte) 1})).isEqualTo(1);
    assertThat(Bytes.byteArrayToInt(new byte[] {(byte) 0x02, (byte) 0x01})).isEqualTo(0x0102);
    assertThat(Bytes.byteArrayToInt(new byte[] {(byte) 0x02, (byte) 0x01}, /* length= */ 2))
        .isEqualTo(0x0102);
    assertThat(
            Bytes.byteArrayToInt(
                new byte[] {(byte) 0x02, (byte) 0x01}, /* offset= */ 0, /* length= */ 2))
        .isEqualTo(0x0102);
    assertThat(
            Bytes.byteArrayToInt(
                new byte[] {(byte) 0x02, (byte) 0x01}, /* offset= */ 1, /* length= */ 1))
        .isEqualTo(0x01);
    assertThat(Bytes.byteArrayToInt(new byte[] {(byte) 0x02, (byte) 0x01}, /* length= */ 1))
        .isEqualTo(0x02);
    assertThat(
            Bytes.byteArrayToInt(
                new byte[] {(byte) 0x05, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x01},
                /* offset= */ 2,
                /* length= */ 1))
        .isEqualTo(3);
  }

  @Test
  public void byteArrayToInt_failsWithInvalidLength() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Bytes.byteArrayToInt(
                new byte[] {(byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x01}));
    assertThrows(
        IllegalArgumentException.class, () -> Bytes.byteArrayToInt(new byte[] {(byte) 0x01}, -1));
  }

  @Test
  public void byteArrayToInt_outOfBounds_fails() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Bytes.byteArrayToInt(new byte[] {(byte) 0x05, (byte) 0x04}, /* length= */ 3));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Bytes.byteArrayToInt(
                new byte[] {(byte) 0x05, (byte) 0x04}, /* offset= */ 1, /* length= */ 2));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Bytes.byteArrayToInt(
                new byte[] {(byte) 0x05, (byte) 0x04}, /* offset= */ -1, /* length= */ 1));
  }
}
