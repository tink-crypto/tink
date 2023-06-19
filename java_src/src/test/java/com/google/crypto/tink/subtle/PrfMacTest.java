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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil.AesCmacTestVector;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class PrfMacTest {

  @DataPoints("allTestVectors")
  public static final AesCmacTestVector[] CMAC_IMPLEMENTATION_TEST_VECTORS =
      new AesCmacTestVector[] {
          AesCmacTestUtil.RFC_TEST_VECTOR_0,
          AesCmacTestUtil.RFC_TEST_VECTOR_1,
          AesCmacTestUtil.RFC_TEST_VECTOR_2,
          AesCmacTestUtil.NOT_OVERFLOWING_INTERNAL_STATE,
          AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE,
          AesCmacTestUtil.FILL_UP_EXACTLY_INTERNAL_STATE_TWICE,
          AesCmacTestUtil.OVERFLOW_INTERNAL_STATE_ONCE,
          AesCmacTestUtil.OVERFLOW_INTERNAL_STATE_TWICE,
          AesCmacTestUtil.SHORTER_TAG,
          AesCmacTestUtil.TAG_WITH_KEY_PREFIX_TYPE_LEGACY,
          AesCmacTestUtil.TAG_WITH_KEY_PREFIX_TYPE_TINK,
          AesCmacTestUtil.LONG_KEY_TEST_VECTOR,
      };

  @DataPoints("failingTestVectors")
  public static final AesCmacTestVector[] CMAC_FAILING_TEST_VECTORS =
      new AesCmacTestVector[] {
          AesCmacTestUtil.WRONG_PREFIX_TAG_LEGACY,
          AesCmacTestUtil.WRONG_PREFIX_TAG_TINK,
          AesCmacTestUtil.TAG_TOO_SHORT
      };

  @Theory
  public void computeMac_isCorrect(
      @FromDataPoints("allTestVectors") AesCmacTestVector t) throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = PrfMac.create(t.key);

    assertThat(aesCmac.computeMac(t.message)).isEqualTo(t.tag);
  }

  @Theory
  public void verifyMac_isCorrect(
      @FromDataPoints("allTestVectors") AesCmacTestVector t) throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = PrfMac.create(t.key);

    aesCmac.verifyMac(t.tag, t.message);
  }

  @Theory
  public void verifyMac_throwsOnWrongTag(
      @FromDataPoints("failingTestVectors") AesCmacTestVector t) throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = PrfMac.create(t.key);

    assertThrows(GeneralSecurityException.class, () -> aesCmac.verifyMac(t.tag, t.message));
  }
}
