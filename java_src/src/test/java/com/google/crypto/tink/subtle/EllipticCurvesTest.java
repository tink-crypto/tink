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

package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link com.google.crypto.tink.subtle.EllipticCurves}. */
@RunWith(JUnit4.class)
public class EllipticCurvesTest {
  // The tests are from
  // http://google.github.io/end-to-end/api/source/src/javascript/crypto/e2e/ecc/ecdh_testdata.js.src.html.

  /**
   * A class for storing test vectors. This class contains the directory for the public and private
   * key, the message and the corresponding signature.
   */
  protected static class TestVector2 {
    protected EllipticCurves.CurveType curve;
    protected EllipticCurves.PointFormatType format;
    protected byte[] encoded;
    BigInteger x;
    BigInteger y;

    protected TestVector2(
        EllipticCurves.CurveType curve,
        EllipticCurves.PointFormatType format,
        String encodedHex,
        String x,
        String y) {
      this.curve = curve;
      this.format = format;
      this.encoded = TestUtil.hexDecode(encodedHex);
      this.x = new BigInteger(x);
      this.y = new BigInteger(y);
    }
  }

  protected static TestVector2[] testVectors2 = {
    // NIST_P256
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04"
            + "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a"
            + "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
        "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a"
            + "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    // Exceptional point: x==0
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
        "0000000000000000000000000000000000000000000000000000000000000000"
            + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.COMPRESSED,
        "020000000000000000000000000000000000000000000000000000000000000000",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    // Exceptional point: x==-3
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04"
            + "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
            + "19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
            + "19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P256,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    // NIST_P384
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a"
            + "385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc"
            + "29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e"
            + "5f",
        "2624703509579968926862315674456698189185292349110921338781561590"
            + "0925518854738050089022388053975719786650872476732087",
        "8325710961489029985546751289520108179287853048861315594709205902"
            + "480503199884419224438643760392947333078086511627871"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a"
            + "385502f25dbf55296c3a545e3872760ab7",
        "2624703509579968926862315674456698189185292349110921338781561590"
            + "0925518854738050089022388053975719786650872476732087",
        "8325710961489029985546751289520108179287853048861315594709205902"
            + "480503199884419224438643760392947333078086511627871"),
    // x = 0
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "00000000000000000000000000000000003cf99ef04f51a5ea630ba3f9f960dd"
            + "593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e52"
            + "1e",
        "0",
        "9384923975005507693384933751151973636103286582194273515051780595"
            + "652610803541482195894618304099771370981414591681054"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0200000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000",
        "0",
        "9384923975005507693384933751151973636103286582194273515051780595"
            + "652610803541482195894618304099771370981414591681054"),
    // x = 2
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000002732152442fb6ee5c3e6ce1d920c059"
            + "bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfd"
            + "b3",
        "2",
        "1772015366480916228638409476801818679957736647795608728422858375"
            + "4887974043472116432532980617621641492831213601947059"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000002",
        "2",
        "1772015366480916228638409476801818679957736647795608728422858375"
            + "4887974043472116432532980617621641492831213601947059"),
    // x = -3
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "feffffffff0000000000000000fffffffc2de9de09a95b74e6b2c430363e1afb"
            + "8dff7164987a8cfe0a0d5139250ac02f797f81092a9bdc0e09b574a8f43bf80c"
            + "17",
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112316",
        "7066741234775658874139271223692271325950306561732202191471600407"
            + "582071247913794644254895122656050391930754095909911"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P384,
        EllipticCurves.PointFormatType.COMPRESSED,
        "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "feffffffff0000000000000000fffffffc",
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112316",
        "7066741234775658874139271223692271325950306561732202191471600407"
            + "582071247913794644254895122656050391930754095909911"),
    // NIST_P521
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b"
            + "4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2"
            + "e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd"
            + "17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94"
            + "769fd16650",
        "2661740802050217063228768716723360960729859168756973147706671368"
            + "4188029449964278084915450806277719023520942412250655586621571135"
            + "45570916814161637315895999846",
        "3757180025770020463545507224491183603594455134769762486694567779"
            + "6155444774405563166912344050129455395621444445372894285225856667"
            + "29196580810124344277578376784"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b"
            + "4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2"
            + "e5bd66",
        "2661740802050217063228768716723360960729859168756973147706671368"
            + "4188029449964278084915450806277719023520942412250655586621571135"
            + "45570916814161637315895999846",
        "3757180025770020463545507224491183603594455134769762486694567779"
            + "6155444774405563166912344050129455395621444445372894285225856667"
            + "29196580810124344277578376784"),
    // x = 0
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "00000000d20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896f"
            + "ee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440"
            + "ae001f4f87",
        "0",
        "2816414230262626695230339754503506208598534788872316917808418392"
            + "0894686826982898181454171638541149642517061885689521392260532032"
            + "30035588176689756661142736775"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000000",
        "0",
        "2816414230262626695230339754503506208598534788872316917808418392"
            + "0894686826982898181454171638541149642517061885689521392260532032"
            + "30035588176689756661142736775"),
    // x = 1
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000010010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03d"
            + "f47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c"
            + "832e843564",
        "1",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0200000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000001",
        "1",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    // x = 2
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "00000200d9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7f"
            + "ce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051"
            + "d6aa505acf",
        "2",
        "2911448509017565583245824537994174021964465504209366849707937264"
            + "0417919148200722009442607963590225526059407040161685364728526719"
            + "10134103604091376779754756815"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000002",
        "2",
        "2911448509017565583245824537994174021964465504209366849707937264"
            + "0417919148200722009442607963590225526059407040161685364728526719"
            + "10134103604091376779754756815"),
    // x = -2
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.UNCOMPRESSED,
        "0401ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "fffffd0010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03d"
            + "f47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c"
            + "832e843564",
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "1855431833976560521225596406614545549772963113914808580371219879"
            + "99716643812574028291115057149",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    new TestVector2(
        EllipticCurves.CurveType.NIST_P521,
        EllipticCurves.PointFormatType.COMPRESSED,
        "0201ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "fffffd",
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "1855431833976560521225596406614545549772963113914808580371219879"
            + "99716643812574028291115057149",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
  };

  @Test
  public void testPointDecode() throws Exception {
    for (TestVector2 test : testVectors2) {
      EllipticCurve curve = EllipticCurves.getCurveSpec(test.curve).getCurve();
      ECPoint p = EllipticCurves.pointDecode(curve, test.format, test.encoded);
      assertEquals(p.getAffineX(), test.x);
      assertEquals(p.getAffineY(), test.y);
    }
  }

  @Test
  public void testPointEncode() throws Exception {
    for (TestVector2 test : testVectors2) {
      EllipticCurve curve = EllipticCurves.getCurveSpec(test.curve).getCurve();
      ECPoint p = new ECPoint(test.x, test.y);
      byte[] encoded = EllipticCurves.pointEncode(curve, test.format, p);
      assertEquals(TestUtil.hexEncode(encoded), TestUtil.hexEncode(test.encoded));
    }
  }

  @Test
  public void pointEncode_failsIfPointIsNotOnCurve() throws Exception {
    // Same an entry of testVectors2, but the value of y has been incremented by 1.
    BigInteger x = new BigInteger(
        "79974177209371530366349631093481213364328002500948308276357601809416549347930");
    BigInteger y = new BigInteger(
           "11093679777528052772423074391650378811758820120351664471899251711300542565880");
    // Adding one to y make the point not be on the curve.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            EllipticCurves.pointEncode(
                EllipticCurves.CurveType.NIST_P256,
                EllipticCurves.PointFormatType.UNCOMPRESSED,
                new ECPoint(x, y)));
  }

  @Test
  public void pointDecode_uncompressed_failsIfPointIsNotOnCurve() throws Exception {
    // Same an entry of testVectors2, but the last byte is changed from f7 to f6
    byte[] encoded = TestUtil.hexDecode("04"
            + "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a"
            + "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df6");
    // Adding one to y make the point not be on the curve.
    assertThrows(GeneralSecurityException.class,
        () -> EllipticCurves.pointDecode(EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED, encoded));
  }

  @Test
  public void pointDecode_crunchy_failsIfPointIsNotOnCurve() throws Exception {
    // Same as an entry of testVectors2, but the last byte is changed from f4 to f5
    byte[] encoded = TestUtil.hexDecode(
        "0000000000000000000000000000000000000000000000000000000000000000"
            + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f5");
    // Adding one to y make the point not be on the curve.
    assertThrows(GeneralSecurityException.class,
        () -> EllipticCurves.pointDecode(EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED, encoded));
  }

  @Test
  public void pointDecode_compressed_failsIfEncodingIsInvalid() throws Exception {
    // Same as an entry of testVectors2, but the last byte is changed from 00 to 01
    byte[] encoded = TestUtil.hexDecode(
        "020000000000000000000000000000000000000000000000000000000000000001");
    assertThrows(GeneralSecurityException.class,
        () -> EllipticCurves.pointDecode(EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.COMPRESSED, encoded));
  }

  /** A class to store a pair of valid Ecdsa signature in IEEE_P1363 and DER format. */
  protected static class EcdsaIeeeDer {
    public String hexIeee;
    public String hexDer;

    protected EcdsaIeeeDer(String hexIeee, String hexDer) {
      this.hexIeee = hexIeee;
      this.hexDer = hexDer;
    }
  };

  protected static EcdsaIeeeDer[] ieeeDerTestVector =
      new EcdsaIeeeDer[] {
        new EcdsaIeeeDer( // normal case, short-form length
            "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10",
            "302402100102030405060708090a0b0c0d0e0f1002100102030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // normal case, long-form length
            "010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203",
            "30818802420100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000002030242010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203"),
        new EcdsaIeeeDer( // zero prefix.
            "0002030405060708090a0b0c0d0e0f100002030405060708090a0b0c0d0e0f10",
            "3022020f02030405060708090a0b0c0d0e0f10020f02030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // highest bit is set.
            "00ff030405060708090a0b0c0d0e0f1000ff030405060708090a0b0c0d0e0f10",
            "3024021000ff030405060708090a0b0c0d0e0f10021000ff030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // highest bit is set, full length.
            "ff02030405060708090a0b0c0d0e0f10ff02030405060708090a0b0c0d0e0f10",
            "3026021100ff02030405060708090a0b0c0d0e0f10021100ff02030405060708090a0b0c0d0e0f10"),
        new EcdsaIeeeDer( // all zeros.
            "0000000000000000000000000000000000000000000000000000000000000000", "3006020100020100"),
      };

  @Test
  public void testEcdsaIeee2Der() throws Exception {
    for (EcdsaIeeeDer test : ieeeDerTestVector) {
      assertArrayEquals(
          Hex.decode(test.hexDer), EllipticCurves.ecdsaIeee2Der(Hex.decode(test.hexIeee)));
    }
  }

  @Test
  public void testEcdsaDer2Ieee() throws Exception {
    for (EcdsaIeeeDer test : ieeeDerTestVector) {
      assertArrayEquals(
          Hex.decode(test.hexIeee),
          EllipticCurves.ecdsaDer2Ieee(Hex.decode(test.hexDer), test.hexIeee.length() / 2));
    }
  }

  protected static String[] invalidEcdsaDers =
      new String[] {
        "2006020101020101", // 1st byte is not 0x30 (SEQUENCE tag)
        "3006050101020101", // 3rd byte is not 0x02 (INTEGER tag)
        "3006020101050101", // 6th byte is not 0x02 (INTEGER tag)
        "308206020101020101", // long form length is not 0x81
        "30ff020101020101", // invalid total length
        "3006020201020101", // invalid rLength
        "3006020101020201", // invalid sLength
        "30060201ff020101", // no extra zero when highest bit of r is set
        "30060201010201ff", // no extra zero when highest bit of s is set
      };

  @Test
  public void testIsValidDerEncoding() throws Exception {
    for (String der : invalidEcdsaDers) {
      assertFalse(EllipticCurves.isValidDerEncoding(Hex.decode(der)));
    }
  }

  @Test
  public void testComputeSharedSecretWithWycheproofTestVectors() throws Exception {
    if (TestUtil.isTsan()) {
      return;
    }

    // NOTE(bleichen): Instead of ecdh_test.json it might be easier to use the
    //   files ecdh_<curve>_ecpoint.json, which encode the public key point just as DER
    //   encoded bitsequence.
    JsonObject json =
        WycheproofTestUtil.readJson("../wycheproof/testvectors/ecdh_test.json");
    int errors = 0;
    JsonArray testGroups = json.get("testGroups").getAsJsonArray();
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();
      JsonArray tests = group.get("tests").getAsJsonArray();
      String curve = group.get("curve").getAsString();
      EllipticCurves.CurveType curveType;
      try {
        curveType = WycheproofTestUtil.getCurveType(curve);
      } catch (NoSuchAlgorithmException ex) {
        System.out.println("Unsupported curve:" + curve);
        continue;
      }
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        if (WycheproofTestUtil.checkFlags(testcase, "CVE_2017_10176")) {
          System.out.println("Skipping CVE-2017-10176 test, see b/73760761");
          continue;
        }

        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        String result = testcase.get("result").getAsString();
        String hexPubKey = testcase.get("public").getAsString();
        String expectedSharedSecret = testcase.get("shared").getAsString();
        String hexPrivKey = testcase.get("private").getAsString();
        if (hexPrivKey.length() % 2 == 1) {
          hexPrivKey = "0" + hexPrivKey;
        }
        KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
        try {
          ECPrivateKey privKey = EllipticCurves.getEcPrivateKey(curveType, Hex.decode(hexPrivKey));
          ECPublicKey pubKey;
          try {
            X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(Hex.decode(hexPubKey));
            pubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
            // Sometimes providers do not encode keys the same way.
            // E.g. BouncyCastle may use long form encoding, where jdk uses a short encoding
            // with named curves. This checks the encodings and logs them if they differ.
            String hexReencodedKey = Hex.encode(pubKey.getEncoded());
            if (!hexPubKey.equals(hexReencodedKey)) {
              System.out.println("Wycheproof encoded public key spec: " + hexPubKey);
              System.out.println("Reencoded public key spec: " + hexReencodedKey);
            }
          } catch (java.lang.RuntimeException ex) {
            // Some of the test vectors contain incorrectly encoded public keys.
            // Some java providers do not properly check the encoding, which often results in
            // RuntimeExceptions. Since the decoding is not part of tink, we can simply ignore
            // these test vectors here.
            System.out.println("Got runtime exception: " + ex);
            continue;
          }
          String sharedSecret = Hex.encode(EllipticCurves.computeSharedSecret(privKey, pubKey));
          if (result.equals("invalid")) {
            if (expectedSharedSecret.equals(sharedSecret)
                && WycheproofTestUtil.checkFlags(
                    testcase, "WrongOrder", "WeakPublicKey", "UnnamedCurve")) {
              System.out.println(
                  tcId + " accepted invalid parameters but shared secret is correct.");
            } else {
              System.out.println(
                  "FAIL " + tcId + " accepted invalid parameters, shared secret: " + sharedSecret);
              errors++;
            }
          } else if (!expectedSharedSecret.equals(sharedSecret)) {
            System.out.println(
                "FAIL "
                    + tcId
                    + " incorrect shared secret, computed: "
                    + sharedSecret
                    + " expected: "
                    + expectedSharedSecret);
            errors++;
          }
        } catch (GeneralSecurityException ex) {
          System.out.println(tcId + " threw exception: " + ex.toString());
          if (result.equals("valid")) {
            System.out.println("FAIL " + tcId + " exception: " + ex.toString());
            ex.printStackTrace();
            errors++;
          }
        } catch (Exception ex) {
          // Other exceptions typically indicate that something is wrong with the implementation.
          System.out.println("FAIL " + tcId + " exception: " + ex.toString());
          ex.printStackTrace();
          errors++;
        }
      }
    }
    assertEquals(0, errors);
  }

  // TODO(b/238096965): Add test that computeSharedSecret checks that the point is on the curve.
}
