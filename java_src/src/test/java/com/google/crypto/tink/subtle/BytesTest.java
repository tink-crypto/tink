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
      x.put((byte) (i));
      y.put((byte) (i + 1));
    }
    x.flip();
    y.flip();
    Bytes.xor(output, x, y, 10);
    for (int i = 0; i < 10; i++) {
      assertEquals(output.get(i), (i) ^ (i + 1));
    }
  }
}
