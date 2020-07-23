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
package com.google.crypto.tink.subtle.prf;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for SingletonPrfSet. */
@RunWith(JUnit4.class)
public final class SingletonPrfSetTest {
  private Prf prf;

  @Before
  public void setUp() {
    prf =
        new Prf() {
          @Override
          public byte[] compute(byte[] input, int outputLength) {
            return input;
          }
        };
  }

  @Test
  public void singletonPrfSet_valid() throws Exception {
    PrfSet prfSet = new SingletonPrfSet(prf);
    assertThat(prfSet.getPrfs()).containsKey(prfSet.getPrimaryId());
    assertThat(prfSet.getPrfs().get(prfSet.getPrimaryId())).isEqualTo(prf);
  }
}
