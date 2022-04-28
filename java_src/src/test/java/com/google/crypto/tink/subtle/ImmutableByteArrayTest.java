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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for ImmutableByteArray */
@RunWith(JUnit4.class)
public class ImmutableByteArrayTest {
  @Test
  public void testBasicWorks() throws Exception {
    byte[] plainArray = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
    ImmutableByteArray array = ImmutableByteArray.of(plainArray);
    assertThat(array.getBytes()).isEqualTo(plainArray);
  }

  @Test
  public void testWithRange() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    ImmutableByteArray array = ImmutableByteArray.of(plainArray, 3, 8);
    assertThat(array.getBytes()).isEqualTo(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});
  }

  @Test
  public void testGetLength() throws Exception {
    byte[] plainArray = new byte[] {100, 100, 100, 0, 1, 2, 3, 4, 5, 6, 7, 100, 100, 100};
    ImmutableByteArray array = ImmutableByteArray.of(plainArray, 3, 8);
    assertThat(array.getLength()).isEqualTo(8);
  }
}
