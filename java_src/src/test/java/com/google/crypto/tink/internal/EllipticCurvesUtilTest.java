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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link com.google.crypto.tink.subtle.EllipticCurvesUtil}. */
@RunWith(JUnit4.class)
public class EllipticCurvesUtilTest {
  // The tests are from
  // http://google.github.io/end-to-end/api/source/src/javascript/crypto/e2e/ecc/ecdh_testdata.js.src.html.
  static class TestVector1 {
    ECParameterSpec curveParams;
    public String pubX;
    public String pubY;

    public TestVector1(ECParameterSpec curveParams, String pubX, String pubY) {
      this.curveParams = curveParams;
      this.pubX = pubX;
      this.pubY = pubY;
    }

    public EllipticCurve getCurve() throws NoSuchAlgorithmException {
      return curveParams.getCurve();
    }
  }

  public static final TestVector1[] testVectors1 =
      new TestVector1[] {
        new TestVector1(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae",
            "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed",
            "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b",
            "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P384_PARAMS,
            "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272"
                + "734466b400091adbf2d68c58e0c50066",
            "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915e"
                + "d0905a32b060992b468c64766fc8437a"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P384_PARAMS,
            "30f43fcf2b6b00de53f624f1543090681839717d53c7c955d1d69efaf0349b736"
                + "3acb447240101cbb3af6641ce4b88e0",
            "25e46c0c54f0162a77efcc27b6ea792002ae2ba82714299c860857a68153ab62e"
                + "525ec0530d81b5aa15897981e858757"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340"
                + "854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2"
                + "046d",
            "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b7398"
                + "84a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302"
                + "f676"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "000001df277c152108349bc34d539ee0cf06b24f5d3500677b4445453ccc21409"
                + "453aafb8a72a0be9ebe54d12270aa51b3ab7f316aa5e74a951c5e53f74cd95fc29a"
                + "ee7a",
            "0000013d52f33a9f3c14384d1587fa8abe7aed74bc33749ad9c570b471776422c"
                + "7d4505d9b0a96b3bfac041e4c6a6990ae7f700e5b4a6640229112deafa0cd8bb0d0"
                + "89b0"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "00000092db3142564d27a5f0006f819908fba1b85038a5bc2509906a497daac67"
                + "fd7aee0fc2daba4e4334eeaef0e0019204b471cd88024f82115d8149cc0cf4f7ce1"
                + "a4d5",
            "0000016bad0623f517b158d9881841d2571efbad63f85cbe2e581960c5d670601"
                + "a6760272675a548996217e4ab2b8ebce31d71fca63fcc3c08e91c1d8edd91cf6fe8"
                + "45f8"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "0000004f38816681771289ce0cb83a5e29a1ab06fc91f786994b23708ff08a08a"
                + "0f675b809ae99e9f9967eb1a49f196057d69e50d6dedb4dd2d9a81c02bdcc8f7f51"
                + "8460",
            "0000009efb244c8b91087de1eed766500f0e81530752d469256ef79f6b965d8a2"
                + "232a0c2dbc4e8e1d09214bab38485be6e357c4200d073b52f04e4a16fc6f5247187"
                + "aecb"),
        new TestVector1(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "000001a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda308b359db"
                + "bc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb7684132795c478ad6f962e4a6f"
                + "446d",
            "0000017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9d387df67c"
                + "de85003e0e427552f1cd09059aad0262e235cce5fba8cedc4fdc1463da76dcd4b6d"
                + "1a46")
      };

  @Test
  public void testPointOnCurve() throws Exception {
    for (EllipticCurvesUtilTest.TestVector1 element : testVectors1) {
      ECPoint pubPoint =
          new ECPoint(new BigInteger(element.pubX, 16), new BigInteger(element.pubY, 16));
      try {
        EllipticCurvesUtil.checkPointOnCurve(pubPoint, element.getCurve());
      } catch (GeneralSecurityException ex) {
        fail("The valid public point is not on the curve: " + ex.getMessage());
      }
    }
  }

  @Test
  public void testPointNotOnCurve() throws Exception {
    for (int j = 0; j < testVectors1.length; j++) {
      final int i = j;
      ECPoint pubPoint =
          new ECPoint(
              new BigInteger(testVectors1[i].pubX, 16),
              new BigInteger(testVectors1[i].pubY, 16).subtract(BigInteger.ONE));
      assertThrows(
          GeneralSecurityException.class,
          () -> EllipticCurvesUtil.checkPointOnCurve(pubPoint, testVectors1[i].getCurve()));
    }
  }

  @Test
  public void testIsSameSpec() throws Exception {
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EllipticCurvesUtil.NIST_P256_PARAMS, EllipticCurvesUtil.NIST_P384_PARAMS))
        .isFalse();
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EllipticCurvesUtil.NIST_P384_PARAMS, EllipticCurvesUtil.NIST_P521_PARAMS))
        .isFalse();
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EllipticCurvesUtil.NIST_P521_PARAMS, EllipticCurvesUtil.NIST_P256_PARAMS))
        .isFalse();
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EllipticCurvesUtil.NIST_P256_PARAMS, EllipticCurvesUtil.NIST_P256_PARAMS))
        .isTrue();
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EllipticCurvesUtil.NIST_P384_PARAMS, EllipticCurvesUtil.NIST_P384_PARAMS))
        .isTrue();
    assertThat(
            EllipticCurvesUtil.isSameEcParameterSpec(
                EllipticCurvesUtil.NIST_P521_PARAMS, EllipticCurvesUtil.NIST_P521_PARAMS))
        .isTrue();
  }

  // Modulus taken from https://safecurves.cr.yp.to/field.html.
  @Test
  public void testModulus() throws Exception {
    BigInteger p256Modulus =
        new BigInteger(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951");
    assertThat(EllipticCurvesUtil.getModulus(EllipticCurvesUtil.NIST_P256_PARAMS.getCurve()))
        .isEqualTo(p256Modulus);
  }
}
