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
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.Mac;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil;
import com.google.crypto.tink.mac.internal.AesCmacTestUtil.AesCmacTestVector;
import com.google.crypto.tink.mac.internal.HmacTestUtil;
import com.google.crypto.tink.mac.internal.HmacTestUtil.HmacTestVector;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class PrfMacTest {
  @BeforeClass
  public static void setUp() throws Exception {
    // If Tink is built in FIPS-only mode, register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test HMAC in FIPS-mode without Conscrypt Provider", cause);
      }
    }

    hmacImplementationTestVectors =
        Arrays.copyOf(
            HmacTestUtil.HMAC_TEST_VECTORS,
            HmacTestUtil.HMAC_TEST_VECTORS.length + HmacTestUtil.PREFIXED_KEY_TYPES.length);
    System.arraycopy(
        HmacTestUtil.PREFIXED_KEY_TYPES,
        0,
        hmacImplementationTestVectors,
        HmacTestUtil.HMAC_TEST_VECTORS.length,
        HmacTestUtil.PREFIXED_KEY_TYPES.length);
  }

  @DataPoints("allAesCmacTestVectors")
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

  @DataPoints("failingAesCmacTestVectors")
  public static final AesCmacTestVector[] CMAC_FAILING_TEST_VECTORS =
      new AesCmacTestVector[] {
        AesCmacTestUtil.WRONG_PREFIX_TAG_LEGACY,
        AesCmacTestUtil.WRONG_PREFIX_TAG_TINK,
        AesCmacTestUtil.TAG_TOO_SHORT
      };

  @DataPoints("failingHmacTestVectors")
  public static final HmacTestVector[] HMAC_FAILING_TEST_VECTORS =
      HmacTestUtil.CREATE_VERIFICATION_FAILS_FAST;

  @DataPoints("allHmacTestVectors")
  public static HmacTestVector[] hmacImplementationTestVectors;

  @Theory
  public void computeAesCmac_isCorrect(@FromDataPoints("allAesCmacTestVectors") AesCmacTestVector t)
      throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = PrfMac.create(t.key);

    assertThat(aesCmac.computeMac(t.message)).isEqualTo(t.tag);
  }

  @Theory
  public void verifyAesCmac_isCorrect(@FromDataPoints("allAesCmacTestVectors") AesCmacTestVector t)
      throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = PrfMac.create(t.key);

    aesCmac.verifyMac(t.tag, t.message);
  }

  @Theory
  public void verifyAesCmac_throwsOnWrongTag(
      @FromDataPoints("failingAesCmacTestVectors") AesCmacTestVector t) throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Mac aesCmac = PrfMac.create(t.key);

    assertThrows(GeneralSecurityException.class, () -> aesCmac.verifyMac(t.tag, t.message));
  }

  @Theory
  public void computeHmac_isCorrect(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    Mac hmac = PrfMac.create(t.key);

    assertThat(hmac.computeMac(t.message)).isEqualTo(t.tag);
  }

  @Theory
  public void verifyHmac_isCorrect(@FromDataPoints("allHmacTestVectors") HmacTestVector t)
      throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    Mac hmac = PrfMac.create(t.key);

    hmac.verifyMac(t.tag, t.message);
  }

  @Theory
  public void verifyHmac_throwsOnWrongTag(
      @FromDataPoints("failingHmacTestVectors") HmacTestVector t) throws Exception {
    assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    Mac hmmac = PrfMac.create(t.key);

    assertThrows(GeneralSecurityException.class, () -> hmmac.verifyMac(t.tag, t.message));
  }
}
