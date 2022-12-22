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
import java.security.spec.ECFieldFp;
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
  static class TestVector {
    ECParameterSpec curveParams;
    public String pubX;
    public String pubY;
    public String privateValue;

    public TestVector(ECParameterSpec curveParams, String pubX, String pubY, String privateValue) {
      this.curveParams = curveParams;
      this.pubX = pubX;
      this.pubY = pubY;
      this.privateValue = privateValue;
    }

    public EllipticCurve getCurve() throws NoSuchAlgorithmException {
      return curveParams.getCurve();
    }
  }

  static TestVector[] testVectors =
      new TestVector[] {
        // Test vectors from https://www.ietf.org/rfc/rfc6979.txt
        new TestVector(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
        new TestVector(
            EllipticCurvesUtil.NIST_P384_PARAMS,
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
                + "DEF8F0EA9055866064A254515480BC13",
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
                + "288B231C3AE0D4FE7344FD2533264720",
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
                + "96D5724E4C70A825F872C9EA60D2EDF5"),
        new TestVector(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
                + "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
                + "3A4",
            "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
                + "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
                + "CF5",
            "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
                + "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
                + "538"),
        // Subset of the test vectors at
        // https://boringssl.googlesource.com/boringssl/+/refs/heads/master/crypto/ecdh_extra/ecdh_tests.txt
        new TestVector(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
            "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
            "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"),
        new TestVector(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d0",
            "8f52b726664cac366fc98ac7a012b2682cbd962e5acb544671d41b9445704d1d",
            "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5"),
        new TestVector(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "d9f2b79c172845bfdb560bbb01447ca5ecc0470a09513b6126902c6b4f8d1051",
            "f815ef5ec32128d3487834764678702e64e164ff7315185e23aff5facd96d7bc",
            "1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8"),
        new TestVector(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "24277c33f450462dcb3d4801d57b9ced05188f16c28eda873258048cd1607e0d",
            "c4789753e2b1f63b32ff014ec42cd6a69fac81dfe6d0d6fd4af372ae27c46f88",
            "207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d"),
        new TestVector(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "9cf4b98581ca1779453cc816ff28b4100af56cf1bf2e5bc312d83b6b1b21d333",
            "7a5504fcac5231a0d12d658218284868229c844a04a3450d6c7381abe080bf3b",
            "85a268f9d7772f990c36b42b0a331adc92b5941de0b862d5d89a347cbf8faab0"),
        new TestVector(
            EllipticCurvesUtil.NIST_P256_PARAMS,
            "a8c5fdce8b62c5ada598f141adb3b26cf254c280b2857a63d2ad783a73115f6b",
            "806e1aafec4af80a0d786b3de45375b517a7e5b51ffb2c356537c9e6ef227d4a",
            "59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf"),
        new TestVector(
            EllipticCurvesUtil.NIST_P384_PARAMS,
            "9803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d3"
                + "4fe4a97bef60cff548355c015dbb3e5f",
            "ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad5"
                + "4dd8b7d73a8abb06a3a3be47d650cc99",
            "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774a"
                + "d463b205da88cf699ab4d43c9cf98a1"),
        new TestVector(
            EllipticCurvesUtil.NIST_P384_PARAMS,
            "ea4018f5a307c379180bf6a62fd2ceceebeeb7d4df063a66fb838aa352434197"
                + "91f7e2c9d4803c9319aa0eb03c416b66",
            "68835a91484f05ef028284df6436fb88ffebabcdd69ab0133e6735a1bcfb3720"
                + "3d10d340a8328a7b68770ca75878a1a6",
            "92860c21bde06165f8e900c687f8ef0a05d14f290b3f07d8b3a8cc6404366e5d51"
                + "19cd6d03fb12dc58e89f13df9cd783"),
        new TestVector(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "00602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240b"
                + "a42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bb"
                + "d945f550a5",
            "01b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946"
                + "eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee"
                + "5cdc88cd2d",
            "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151"
                + "f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6f"
                + "c47"),
        new TestVector(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "00d45615ed5d37fde699610a62cd43ba76bedd8f85ed31005fe00d6450fbbd10"
                + "1291abd96d4945a8b57bc73b3fe9f4671105309ec9b6879d0551d930da"
                + "c8ba45d255",
            "01425332844e592b440c0027972ad1526431c06732df19cd46a242172d4dd67c"
                + "2c8c99dfc22e49949a56cf90c6473635ce82f25b33682fb19bc33bd910"
                + "ed8ce3a7fa",
            "00816f19c1fb10ef94d4a1d81c156ec3d1de08b66761f03f06ee4bb9dcebbb"
                + "fe1eaa1ed49a6a990838d8ed318c14d74cc872f95d05d07ad50f621ceb620cd905c"
                + "fb8"),
        new TestVector(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "00717fcb3d4a40d103871ede044dc803db508aaa4ae74b70b9fb8d8dfd84bfec"
                + "fad17871879698c292d2fd5e17b4f9343636c531a4fac68a35a9366554"
                + "6b9a878679",
            "00f3d96a8637036993ab5d244500fff9d2772112826f6436603d3eb234a44d5c"
                + "4e5c577234679c4f9df725ee5b9118f23d8a58d0cc01096daf70e8dfec"
                + "0128bdc2e8",
            "012f2e0c6d9e9d117ceb9723bced02eb3d4eebf5feeaf8ee0113ccd8057b13"
                + "ddd416e0b74280c2d0ba8ed291c443bc1b141caf8afb3a71f97f57c225c03e1e4d4"
                + "2b0"),
        new TestVector(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "00c825ba307373cec8dd2498eef82e21fd9862168dbfeb83593980ca9f828753"
                + "33899fe94f137daf1c4189eb502937c3a367ea7951ed8b0f3377fcdf29"
                + "22021d46a5",
            "016b8a2540d5e65493888bc337249e67c0a68774f3e8d81e3b4574a0125165f0"
                + "bd58b8af9de74b35832539f95c3cd9f1b759408560aa6851ae3ac75553"
                + "47b0d3b13b",
            "005dc33aeda03c2eb233014ee468dff753b72f73b00991043ea353828ae69d"
                + "4cd0fadeda7bb278b535d7c57406ff2e6e473a5a4ff98e90f90d6dadd25100e8d85"
                + "666"),
        new TestVector(
            EllipticCurvesUtil.NIST_P521_PARAMS,
            "004e8583bbbb2ecd93f0714c332dff5ab3bc6396e62f3c560229664329baa513"
                + "8c3bb1c36428abd4e23d17fcb7a2cfcc224b2e734c8941f6f121722d7b"
                + "6b94154576",
            "01cf0874f204b0363f020864672fadbf87c8811eb147758b254b74b14fae7421"
                + "59f0f671a018212bbf25b8519e126d4cad778cfff50d288fd39ceb0cac"
                + "635b175ec0",
            "00df14b1f1432a7b0fb053965fd8643afee26b2451ecb6a8a53a655d5fbe16"
                + "e4c64ce8647225eb11e7fdcb23627471dffc5c2523bd2ae89957cba3a57a23933e5"
                + "a78")
      };

  @Test
  public void testPointOnCurve() throws Exception {
    for (EllipticCurvesUtilTest.TestVector element : testVectors) {
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
    for (int j = 0; j < testVectors.length; j++) {
      final int i = j;
      ECPoint pubPoint =
          new ECPoint(
              new BigInteger(testVectors[i].pubX, 16),
              new BigInteger(testVectors[i].pubY, 16).subtract(BigInteger.ONE));
      assertThrows(
          GeneralSecurityException.class,
          () -> EllipticCurvesUtil.checkPointOnCurve(pubPoint, testVectors[i].getCurve()));
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

  @Test
  public void convertToJacobianAndBack_isEqual() throws Exception {
    for (EllipticCurvesUtilTest.TestVector element : testVectors) {
      BigInteger modulus = EllipticCurvesUtil.getModulus(element.curveParams.getCurve());
      ECPoint point =
          new ECPoint(new BigInteger(element.pubX, 16), new BigInteger(element.pubY, 16));
      assertThat(EllipticCurvesUtil.toJacobianEcPoint(point, modulus).toECPoint(modulus))
          .isEqualTo(point);
    }
  }

  @Test
  public void doubleJacobianPointInfinity() throws Exception {
    BigInteger modulus = BigInteger.TEN;
    EllipticCurvesUtil.JacobianEcPoint inf =
        EllipticCurvesUtil.toJacobianEcPoint(ECPoint.POINT_INFINITY, modulus);
    EllipticCurvesUtil.JacobianEcPoint inf2 =
        EllipticCurvesUtil.doubleJacobianPoint(inf, BigInteger.valueOf(3), modulus);
    assertThat(inf2.isInfinity()).isTrue();
  }

  @Test
  public void addJacobianPointsWithInfinity() throws Exception {
    BigInteger p = EllipticCurvesUtil.getModulus(EllipticCurvesUtil.NIST_P256_PARAMS.getCurve());
    EllipticCurvesUtil.JacobianEcPoint inf =
        EllipticCurvesUtil.toJacobianEcPoint(ECPoint.POINT_INFINITY, p);
    ECPoint point =
        new ECPoint(
            new BigInteger("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287", 16),
            new BigInteger("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac", 16));
    EllipticCurvesUtil.JacobianEcPoint jpoint = EllipticCurvesUtil.toJacobianEcPoint(point, p);
    assertThat(
            EllipticCurvesUtil.addJacobianPoints(jpoint, inf, BigInteger.valueOf(3), p)
                .toECPoint(p))
        .isEqualTo(point);
    assertThat(
            EllipticCurvesUtil.addJacobianPoints(inf, jpoint, BigInteger.valueOf(3), p)
                .toECPoint(p))
        .isEqualTo(point);
    EllipticCurvesUtil.JacobianEcPoint inf2 =
        EllipticCurvesUtil.addJacobianPoints(inf, inf, BigInteger.valueOf(3), p);
    assertThat(inf2.isInfinity()).isTrue();
  }

  @Test
  public void addJacobianPointsWithEqualXCoordinates_returnsInfinity() throws Exception {
    BigInteger p = EllipticCurvesUtil.getModulus(EllipticCurvesUtil.NIST_P256_PARAMS.getCurve());
    EllipticCurvesUtil.JacobianEcPoint point1 =
        EllipticCurvesUtil.toJacobianEcPoint(
            new ECPoint(
                BigInteger.ZERO,
                new BigInteger(
                    "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4", 16)),
            p);
    EllipticCurvesUtil.JacobianEcPoint point2 =
        EllipticCurvesUtil.toJacobianEcPoint(
            new ECPoint(
                BigInteger.ZERO,
                new BigInteger(
                    "99b7a386f1d07c29dbcc42a27b5f9449abe3d50de25178e8d7407a95e8b06c0b", 16)),
            p);

    // These points have the same x coordinate, so their sum must be the infinity point.
    EllipticCurvesUtil.JacobianEcPoint output =
        EllipticCurvesUtil.addJacobianPoints(point1, point2, BigInteger.valueOf(3), p);
    assertThat(output.isInfinity()).isTrue();
  }

  @Test
  public void ecPointOperationsAreConsistent() throws Exception {
    BigInteger p = EllipticCurvesUtil.getModulus(EllipticCurvesUtil.NIST_P256_PARAMS.getCurve());
    BigInteger a = EllipticCurvesUtil.NIST_P256_PARAMS.getCurve().getA();
    ECPoint point = EllipticCurvesUtil.NIST_P256_PARAMS.getGenerator();
    EllipticCurvesUtil.JacobianEcPoint jpoint = EllipticCurvesUtil.toJacobianEcPoint(point, p);
    EllipticCurvesUtil.JacobianEcPoint jpoint2 =
        EllipticCurvesUtil.addJacobianPoints(jpoint, jpoint, a, p);
    EllipticCurvesUtil.JacobianEcPoint jpoint3 =
        EllipticCurvesUtil.addJacobianPoints(jpoint2, jpoint, a, p);
    EllipticCurvesUtil.JacobianEcPoint jpoint4 =
        EllipticCurvesUtil.addJacobianPoints(jpoint3, jpoint, a, p);

    point = jpoint.toECPoint(p);
    ECPoint point2 = jpoint2.toECPoint(p);
    ECPoint point3 = jpoint3.toECPoint(p);
    ECPoint point4 = jpoint4.toECPoint(p);

    // All these points should be on P256.
    EllipticCurvesUtil.checkPointOnCurve(point, EllipticCurvesUtil.NIST_P256_PARAMS.getCurve());
    EllipticCurvesUtil.checkPointOnCurve(point2, EllipticCurvesUtil.NIST_P256_PARAMS.getCurve());
    EllipticCurvesUtil.checkPointOnCurve(point3, EllipticCurvesUtil.NIST_P256_PARAMS.getCurve());
    EllipticCurvesUtil.checkPointOnCurve(point4, EllipticCurvesUtil.NIST_P256_PARAMS.getCurve());

    // Other ways to calculate these points. All calculations should be consistent.
    assertThat(EllipticCurvesUtil.doubleJacobianPoint(jpoint, a, p).toECPoint(p)).isEqualTo(point2);
    assertThat(EllipticCurvesUtil.doubleJacobianPoint(jpoint2, a, p).toECPoint(p))
        .isEqualTo(point4);
    assertThat(EllipticCurvesUtil.addJacobianPoints(jpoint, jpoint2, a, p).toECPoint(p))
        .isEqualTo(point3);
    assertThat(EllipticCurvesUtil.addJacobianPoints(jpoint, jpoint3, a, p).toECPoint(p))
        .isEqualTo(point4);
    assertThat(EllipticCurvesUtil.addJacobianPoints(jpoint2, jpoint2, a, p).toECPoint(p))
        .isEqualTo(point4);
    assertThat(
            EllipticCurvesUtil.multiplyByGenerator(
                BigInteger.ONE, EllipticCurvesUtil.NIST_P256_PARAMS))
        .isEqualTo(point);
    assertThat(
            EllipticCurvesUtil.multiplyByGenerator(
                BigInteger.valueOf(2), EllipticCurvesUtil.NIST_P256_PARAMS))
        .isEqualTo(point2);
    assertThat(
            EllipticCurvesUtil.multiplyByGenerator(
                BigInteger.valueOf(3), EllipticCurvesUtil.NIST_P256_PARAMS))
        .isEqualTo(point3);
    assertThat(
            EllipticCurvesUtil.multiplyByGenerator(
                BigInteger.valueOf(4), EllipticCurvesUtil.NIST_P256_PARAMS))
        .isEqualTo(point4);
  }

  @Test
  public void multiplyByGenerator_kIsOutOfRange_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EllipticCurvesUtil.multiplyByGenerator(
                BigInteger.ZERO, EllipticCurvesUtil.NIST_P256_PARAMS));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EllipticCurvesUtil.multiplyByGenerator(
                BigInteger.valueOf(-1), EllipticCurvesUtil.NIST_P256_PARAMS));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EllipticCurvesUtil.multiplyByGenerator(
                EllipticCurvesUtil.NIST_P256_PARAMS.getOrder(),
                EllipticCurvesUtil.NIST_P256_PARAMS));
  }

  @Test
  public void multiplyByGeneratorOnTestVectors() throws Exception {
    for (EllipticCurvesUtilTest.TestVector element : testVectors) {
      BigInteger privateValue = new BigInteger(element.privateValue, 16);

      ECPoint output = EllipticCurvesUtil.multiplyByGenerator(privateValue, element.curveParams);
      EllipticCurvesUtil.checkPointOnCurve(output, element.getCurve());

      ECPoint expectedPublicPoint =
          new ECPoint(new BigInteger(element.pubX, 16), new BigInteger(element.pubY, 16));
      assertThat(output).isEqualTo(expectedPublicPoint);
    }
  }

  /* This is the same as NIST_P256_PARAMS, but with a different generator. */
  private static ECParameterSpec p256WithDifferentGenerator() {
    final BigInteger p =
        new BigInteger(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951");
    final BigInteger n =
        new BigInteger(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369");
    final BigInteger three = new BigInteger("3");
    final BigInteger a = p.subtract(three);
    final BigInteger b =
        new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    // The point (gx, gy) is on the curve, but is not the NIST generator.
    final BigInteger gx =
        new BigInteger("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16);
    final BigInteger gy =
        new BigInteger("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16);
    final int h = 1;
    ECFieldFp fp = new ECFieldFp(p);
    EllipticCurve curveSpec = new EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(gx, gy);
    return new ECParameterSpec(curveSpec, g, n, h);
  }

  @Test
  public void multiplyByGenerator_nonNistSpec_throws() throws Exception {
    ECParameterSpec nonNistSpec = p256WithDifferentGenerator();
    assertThrows(
        GeneralSecurityException.class,
        () -> EllipticCurvesUtil.multiplyByGenerator(BigInteger.TEN, nonNistSpec));
  }
}
