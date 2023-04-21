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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class PredefinedDeterministicAeadParametersTest {
  @BeforeClass
  public static void setUp() throws Exception {
    DeterministicAeadConfig.register();
  }

  @Test
  public void testNotNull() {
    assertThat(PredefinedDeterministicAeadParameters.AES256_SIV).isNotNull();
  }

  @Test
  public void testInstantiation()
      throws Exception {
    Key key =
        KeysetHandle.generateNew(PredefinedDeterministicAeadParameters.AES256_SIV)
            .getAt(0)
            .getKey();
    assertThat(key.getParameters()).isEqualTo(PredefinedDeterministicAeadParameters.AES256_SIV);
  }
}
