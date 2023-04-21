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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class PredefinedPrfParametersTest {
  @BeforeClass
  public static void setUp() throws Exception {
    PrfConfig.register();
  }

  @DataPoints("AllParameters")
  public static final PrfParameters[] TEMPLATES =
      new PrfParameters[] {
        PredefinedPrfParameters.HKDF_SHA256,
        PredefinedPrfParameters.HMAC_SHA256_PRF,
        PredefinedPrfParameters.HMAC_SHA512_PRF,
        PredefinedPrfParameters.AES_CMAC_PRF,
      };

  @Theory
  public void testInstantiation(@FromDataPoints("AllParameters") PrfParameters parameters)
      throws Exception {
    Key key = KeysetHandle.generateNew(parameters).getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(parameters);
  }
}
