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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.StreamingTestUtil.PseudorandomReadableByteChannel;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for RewindableReadableByteChannel */
@RunWith(JUnit4.class)
public class RewindableReadableByteChannelTest {

  @Test
  public void testSingleReadsOfVariousLengths() throws Exception {
    int inputSize = 1234;
    ReadableByteChannel baseChannel = new PseudorandomReadableByteChannel(inputSize);
    assertTrue(baseChannel.isOpen());
    RewindableReadableByteChannel rewindableChannel =
        new RewindableReadableByteChannel(baseChannel);
    assertTrue(rewindableChannel.isOpen());

    // Read some initial bytes.
    int buffer1Size = 42;
    ByteBuffer buffer1 = ByteBuffer.allocate(buffer1Size);
    assertEquals(buffer1Size, rewindableChannel.read(buffer1));

    // Rewind, and read a shorter sequence of initial bytes.
    rewindableChannel.rewind();
    int buffer2Size = 40;
    ByteBuffer buffer2 = ByteBuffer.allocate(buffer2Size);
    assertEquals(buffer2Size, rewindableChannel.read(buffer2));
    assertArrayEquals(buffer2.array(), Arrays.copyOfRange(buffer1.array(), 0, buffer2Size));

    // Rewind, and read a longer sequence of initial bytes.
    rewindableChannel.rewind();
    int buffer3Size = 60;
    ByteBuffer buffer3 = ByteBuffer.allocate(buffer3Size);
    assertEquals(buffer3Size, rewindableChannel.read(buffer3));
    assertArrayEquals(buffer1.array(), Arrays.copyOfRange(buffer3.array(), 0, buffer1Size));

    // Read all the remaining bytes.
    int buffer4Size = inputSize - buffer3Size;
    ByteBuffer buffer4 = ByteBuffer.allocate(buffer4Size);
    assertEquals(buffer4Size, rewindableChannel.read(buffer4));

    // Check that no more bytes are left.
    ByteBuffer buffer5 = ByteBuffer.allocate(inputSize);
    assertEquals(-1, rewindableChannel.read(buffer5));

    // Rewind, and read the entire file again.
    rewindableChannel.rewind();
    assertEquals(inputSize, rewindableChannel.read(buffer5));
    assertArrayEquals(buffer4.array(),
        Arrays.copyOfRange(buffer5.array(), buffer3Size, inputSize));

    // Close the channel.
    rewindableChannel.close();
    assertFalse(rewindableChannel.isOpen());
    assertFalse(baseChannel.isOpen());

    // Try rewinding or reading after closing.
    try {
      rewindableChannel.rewind();
      fail("Should have thrown exception, as cannot rewind after closing.");
    } catch (IOException expected) {
      assertExceptionContains(expected, "Cannot rewind");
    }
    ByteBuffer buffer6 = ByteBuffer.allocate(42);
    try {
      int unused = rewindableChannel.read(buffer6);
      fail("Should have thrown exception, as cannot read after closing.");
    } catch (ClosedChannelException expected) {
    }
  }

  @Test
  public void testSubsequentReads() throws Exception {
    int inputSize = 1234;
    ReadableByteChannel baseChannel = new PseudorandomReadableByteChannel(inputSize);
    assertTrue(baseChannel.isOpen());
    RewindableReadableByteChannel rewindableChannel =
        new RewindableReadableByteChannel(baseChannel);
    assertTrue(rewindableChannel.isOpen());

    // Read some initial bytes.
    int buffer1Size = 105;
    ByteBuffer buffer1 = ByteBuffer.allocate(buffer1Size);
    int limit1 = 42;
    buffer1.limit(limit1);
    assertEquals(limit1, rewindableChannel.read(buffer1));

    // Continue reading until the buffer is full.
    buffer1.limit(buffer1.capacity());
    assertEquals(buffer1Size - limit1, rewindableChannel.read(buffer1));

    // Rewind, and read a longer sequence of initial bytes.
    rewindableChannel.rewind();
    int buffer2Size = 160;
    ByteBuffer buffer2 = ByteBuffer.allocate(buffer2Size);
    assertEquals(buffer2Size, rewindableChannel.read(buffer2));
    assertArrayEquals(buffer1.array(), Arrays.copyOfRange(buffer2.array(), 0, buffer1Size));

    // Rewind, and read a longer sequence in multiple steps.
    rewindableChannel.rewind();
    int buffer3Size = 150;
    ByteBuffer buffer3 = ByteBuffer.allocate(buffer3Size);
    int stepCount = 5;
    int blockSize = buffer3Size / stepCount;
    for (int i = 1; i <= stepCount; i++) {
      buffer3.limit(i * blockSize);
      assertEquals(blockSize, rewindableChannel.read(buffer3));
    }
    assertArrayEquals(buffer3.array(), Arrays.copyOfRange(buffer2.array(), 0, buffer3Size));

    // Read the remaining bytes and check the size;
    ByteBuffer buffer4 = ByteBuffer.allocate(inputSize);
    assertEquals(inputSize - buffer3Size, rewindableChannel.read(buffer4));
    assertEquals(-1, rewindableChannel.read(buffer4));

    // Close the channel.
    rewindableChannel.close();
    assertFalse(rewindableChannel.isOpen());
    assertFalse(baseChannel.isOpen());
  }

  @Test
  public void testDisableRewind() throws Exception {
    int blockSize = PseudorandomReadableByteChannel.BLOCK_SIZE;
    int extraSize = 123;
    int blockCount = 5;
    int inputSize = blockSize * blockCount + extraSize;
    ReadableByteChannel baseChannel = new PseudorandomReadableByteChannel(inputSize);
    assertTrue(baseChannel.isOpen());
    RewindableReadableByteChannel rewindableChannel =
        new RewindableReadableByteChannel(baseChannel);
    assertTrue(rewindableChannel.isOpen());

    // Read two blocks.
    ByteBuffer twoBlocksBuffer = ByteBuffer.allocate(2 * blockSize);
    assertEquals(2 * blockSize, rewindableChannel.read(twoBlocksBuffer));
    // Verify that the read bytes are not all the same.
    assertFalse(Arrays.equals(Arrays.copyOfRange(twoBlocksBuffer.array(), 0, 42),
            Arrays.copyOfRange(twoBlocksBuffer.array(), 42, 2 * 42)));

    // Rewind and read 1 block + extraSize;
    rewindableChannel.rewind();
    ByteBuffer blockAndExtraBuffer = ByteBuffer.allocate(blockSize + extraSize);
    assertEquals(blockSize + extraSize, rewindableChannel.read(blockAndExtraBuffer));
    assertArrayEquals(blockAndExtraBuffer.array(),
        Arrays.copyOfRange(twoBlocksBuffer.array(), 0, blockSize + extraSize));

    // Disable the rewinding feature, and continue reading.
    rewindableChannel.disableRewinding();
    try {
      rewindableChannel.rewind();
      fail("Should have thrown exception, as rewinding has been dropped");
    } catch (IOException expected) {
      assertExceptionContains(expected, "Cannot rewind");
    }
    ByteBuffer oneBlockBuffer = ByteBuffer.allocate(blockSize);
    assertEquals(blockSize, rewindableChannel.read(oneBlockBuffer));
    assertArrayEquals(oneBlockBuffer.array(),
        Arrays.copyOfRange(twoBlocksBuffer.array(), extraSize, blockSize + extraSize));

    int remainingSize = (blockCount - 2) * blockSize;
    ByteBuffer remainingBuffer = ByteBuffer.allocate(remainingSize);
    assertEquals(remainingSize, rewindableChannel.read(remainingBuffer));
    assertArrayEquals(blockAndExtraBuffer.array(),
        Arrays.copyOfRange(remainingBuffer.array(),
            remainingSize - blockSize - extraSize, remainingSize));

    // Check EOF.
    ByteBuffer buffer = ByteBuffer.allocate(42);
    assertEquals(-1, rewindableChannel.read(buffer));

    // Close the channel.
    rewindableChannel.close();
    assertFalse(rewindableChannel.isOpen());
    assertFalse(baseChannel.isOpen());
  }

  @Test
  public void testExceptions() throws Exception {
    int inputSize = 1234;
    ReadableByteChannel baseChannel = new PseudorandomReadableByteChannel(inputSize);
    baseChannel.close();
    assertFalse(baseChannel.isOpen());
    RewindableReadableByteChannel rewindableChannel =
        new RewindableReadableByteChannel(baseChannel);
    assertFalse(rewindableChannel.isOpen());

    ByteBuffer buffer = ByteBuffer.allocate(42);
    try {
      int unused = rewindableChannel.read(buffer);
      fail("Should have thrown exception, as cannot read after closing.");
    } catch (ClosedChannelException expected) {
    }
  }
}
