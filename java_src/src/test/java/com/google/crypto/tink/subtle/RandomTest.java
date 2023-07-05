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

package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RandomTest {

  @Test
  public void randdomBytes_areDifferent() throws Exception {
    assertThat(Random.randBytes(10)).isNotEqualTo(Random.randBytes(10));
  }

  @Test
  public void randIntWithMax_works() throws Exception {
    assertThat(Random.randInt(5)).isLessThan(5);
  }

  @Test
  public void randInt_works() throws Exception {
    int unused = Random.randInt();
  }
}
