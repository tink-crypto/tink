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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for ImmutableByteArray */
@RunWith(JUnit4.class)
public class ImmutableByteArrayTest {

  @Test
  public void checkWrap() {
    byte[] initial = new byte[] {(byte) 1};
    ImmutableByteArray ba = ImmutableByteArray.of(initial);
    byte[] result = ba.getBytes();
    assertNotSame(result, initial);
    assertArrayEquals(result, initial);
    assertEquals(ba.getLength(), initial.length);
  }
}
