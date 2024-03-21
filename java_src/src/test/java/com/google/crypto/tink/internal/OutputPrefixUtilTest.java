// Copyright 2024 Google Inc.
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

import com.google.crypto.tink.util.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class OutputPrefixUtilTest {

  @Test
  public void getTinkOutputPrefix_works() {
    Bytes prefix = OutputPrefixUtil.getTinkOutputPrefix(0x12345678);
    assertThat(prefix)
        .isEqualTo(
            Bytes.copyFrom(
                new byte[] {(byte) 0x01, (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78}));
    assertThat(prefix.size()).isEqualTo(OutputPrefixUtil.NON_EMPTY_PREFIX_SIZE);
  }

  @Test
  public void getLegacyOutputPrefix_works() {
    Bytes prefix = OutputPrefixUtil.getLegacyOutputPrefix(0x12345678);
    assertThat(prefix)
        .isEqualTo(
            Bytes.copyFrom(
                new byte[] {(byte) 0x00, (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78}));
    assertThat(prefix.size()).isEqualTo(OutputPrefixUtil.NON_EMPTY_PREFIX_SIZE);
  }

  @Test
  public void emptyPrefix_isEmpty() {
    assertThat(OutputPrefixUtil.EMPTY_PREFIX).isEqualTo(Bytes.copyFrom(new byte[] {}));
  }
}
