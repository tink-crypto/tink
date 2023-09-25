// Copyright 2023 Google LLC
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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class StutteringInputStreamTest {
  @Test
  public void testNoArgsRead_works() throws Exception {
    byte[] b = new byte[] {(byte) 254, 0, (byte) 255};
    StutteringInputStream s = StutteringInputStream.copyFrom(b);
    assertThat(s.read()).isEqualTo(254);
    assertThat(s.read()).isEqualTo(0);
    assertThat(s.read()).isEqualTo(255);
    assertThat(s.read()).isEqualTo(-1);
  }

  @Test
  public void testWithBuffer_works() throws Exception {
    byte[] b = new byte[] {(byte) 254, 0, (byte) 255};
    StutteringInputStream s = StutteringInputStream.copyFrom(b);

    byte[] buffer = new byte[10];
    assertThat(s.read(buffer, 0, 10)).isEqualTo(1);
    assertThat(buffer).isEqualTo(new byte[] {(byte) 254, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    assertThat(s.read(buffer, 0, 10)).isEqualTo(1);
    assertThat(buffer).isEqualTo(new byte[] {(byte) 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    assertThat(s.read(buffer, 0, 10)).isEqualTo(1);
    assertThat(buffer).isEqualTo(new byte[] {(byte) 255, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    assertThat(s.read(buffer, 0, 10)).isEqualTo(-1);
  }

  @Test
  public void testWithBuffer_len0() throws Exception {
    byte[] b = new byte[] {(byte) 254, 0, (byte) 255};
    StutteringInputStream s = StutteringInputStream.copyFrom(b);
    assertThat(s.read(b, 0, 0)).isEqualTo(0);
  }
}
