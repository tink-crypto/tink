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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.WycheproofTestUtil;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link com.google.crypto.tink.subtle.EllipticCurves}. */
@RunWith(JUnit4.class)
public class EllipticCurvesTest {
  // The tests are from
  // http://google.github.io/end-to-end/api/source/src/javascript/crypto/e2e/ecc/ecdh_testdata.js.src.html.
  static class TestVector1 {
    EllipticCurves.CurveType curve;
    public String pubX;
    public String pubY;

    public TestVector1(EllipticCurves.CurveType curve, String pubX, String pubY) {
      this.curve = curve;
      this.pubX = pubX;
      this.pubY = pubY;
    }

    public EllipticCurve getCurve() throws NoSuchAlgorithmException {
      return EllipticCurves.getCurveSpec(curve).getCurve();
    }
  }

  public static final TestVector1[] testVectors1 =
      new TestVector1[] {
        new TestVector1(
            EllipticCurves.CurveType.NIST_P256,
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P256,
            "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae",
            "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P256,
            "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed",
            "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P256,
            "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b",
            "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P384,
            "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272"
                + "734466b400091adbf2d68c58e0c50066",
            "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915e"
                + "d0905a32b060992b468c64766fc8437a"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P384,
            "30f43fcf2b6b00de53f624f1543090681839717d53c7c955d1d69efaf0349b736"
                + "3acb447240101cbb3af6641ce4b88e0",
            "25e46c0c54f0162a77efcc27b6ea792002ae2ba82714299c860857a68153ab62e"
                + "525ec0530d81b5aa15897981e858757"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P521,
            "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340"
                + "854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2"
                + "046d",
            "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b7398"
                + "84a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302"
                + "f676"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P521,
            "000001df277c152108349bc34d539ee0cf06b24f5d3500677b4445453ccc21409"
                + "453aafb8a72a0be9ebe54d12270aa51b3ab7f316aa5e74a951c5e53f74cd95fc29a"
                + "ee7a",
            "0000013d52f33a9f3c14384d1587fa8abe7aed74bc33749ad9c570b471776422c"
                + "7d4505d9b0a96b3bfac041e4c6a6990ae7f700e5b4a6640229112deafa0cd8bb0d0"
                + "89b0"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P521,
            "00000092db3142564d27a5f0006f819908fba1b85038a5bc2509906a497daac67"
                + "fd7aee0fc2daba4e4334eeaef0e0019204b471cd88024f82115d8149cc0cf4f7ce1"
                + "a4d5",
            "0000016bad0623f517b158d9881841d2571efbad63f85cbe2e581960c5d670601"
                + "a6760272675a548996217e4ab2b8ebce31d71fca63fcc3c08e91c1d8edd91cf6fe8"
                + "45f8"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P521,
            "0000004f38816681771289ce0cb83a5e29a1ab06fc91f786994b23708ff08a08a"
                + "0f675b809ae99e9f9967eb1a49f196057d69e50d6dedb4dd2d9a81c02bdcc8f7f51"
                + "8460",
            "0000009efb244c8b91087de1eed766500f0e81530752d469256ef79f6b965d8a2"
                + "232a0c2dbc4e8e1d09214bab38485be6e357c4200d073b52f04e4a16fc6f5247187"
                + "aecb"),
        new TestVector1(
            EllipticCurves.CurveType.NIST_P521,
            "000001a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda308b359db"
                + "bc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb7684132795c478ad6f962e4a6f"
                + "446d",
            "0000017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9d387df67c"
                + "de85003e0e427552f1cd09059aad0262e235cce5fba8cedc4fdc1463da76dcd4b6d"
                + "1a46")
      };

  @Test
  public void testPointOnCurve() throws Exception {
    for (int i = 0; i < testVectors1.length; i++) {
      ECPoint pubPoint =
          new ECPoint(
              new BigInteger(testVectors1[i].pubX, 16), new BigInteger(testVectors1[i].pubY, 16));
      try {
        EllipticCurves.checkPointOnCurve(pubPoint, testVectors1[i].getCurve());
      } catch (GeneralSecurityException ex) {
        fail("The valid public point is not on the curve: " + ex.getMessage());
      }
    }
  }

  @Test
  public void testPointNotOnCurve() throws Exception {
    for (int i = 0; i < testVectors1.length; i++) {
      ECPoint pubPoint =
          new ECPoint(
              new BigInteger(testVectors1[i].pubX, 16),
              new BigInteger(testVectors1[i].pubY, 16).subtract(BigInteger.ONE));
      try {
        EllipticCurves.checkPointOnCurve(pubPoint, testVectors1[i].getCurve());
        fail("The point is not on the curve");
      } catch (GeneralSecurityException expected) {
        // Expected
      }
    }
  }

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
  public void testCheckPublicKeyWithPointNotOnCurve() throws Exception {
    JSONObject json = WycheproofTestUtil.readJson("testdata/wycheproof/ecdh_test.json");
    WycheproofTestUtil.checkAlgAndVersion(json, "ECDH", "0.1.3");
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        int tcid = testcase.getInt("tcId");
        // Test vectors 139, 140, 141 contain public points that aren't on the curve.
        if (tcid < 139 || tcid > 141) {
          continue;
        }
        String hexPubKey = testcase.getString("public");
        KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
        try {
          X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(Hex.decode(hexPubKey));
          ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
          EllipticCurves.checkPublicKey(pubKey);
          fail("Public point not on curve shouldn't be accepted, test case: " + tcid);
        } catch (GeneralSecurityException ex) {
          // Expected, since the public point is not on the curve.
          System.out.println("testCheckPublicKeyWithPointNotOnCurve, throws " + ex.toString());
        }
      }
    }
  }

  @Test
  public void testComputeSharedSecretWithWycheproofTestVectors() throws Exception {
    JSONObject json = WycheproofTestUtil.readJson("testdata/wycheproof/ecdh_test.json");
    WycheproofTestUtil.checkAlgAndVersion(json, "ECDH", "0.1.3");
    int numTests = json.getInt("numberOfTests");
    int passedTests = 0;
    int rejectedTests = 0; // invalid test vectors leading to exceptions
    int skippedTests = 0; // valid test vectors leading to exceptions
    int errors = 0;
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        int tcid = testcase.getInt("tcId");
        // Skips known issue CVE-2017-10176 which hasn't been fixed in some OpenJDK versions.
        if (tcid == 137) {
          skippedTests++;
          continue;
        }
        String comment = testcase.getString("comment");
        String tc = "tcId: " + tcid + " comment: " + comment;
        String result = testcase.getString("result");
        String hexPubKey = testcase.getString("public");
        String expectedSharedSecret = testcase.getString("shared");
        String curve = testcase.getString("curve");
        String hexPrivKey = testcase.getString("private");
        if (hexPrivKey.length() % 2 == 1) {
          hexPrivKey = "0" + hexPrivKey;
        }
        KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
        try {
          EllipticCurves.CurveType curveType = WycheproofTestUtil.getCurveType(curve);
          ECPrivateKey privKey = EllipticCurves.getEcPrivateKey(curveType, Hex.decode(hexPrivKey));
          X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(Hex.decode(hexPubKey));
          ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
          String sharedSecret = Hex.encode(EllipticCurves.computeSharedSecret(privKey, pubKey));
          if (result.equals("invalid")) {
            System.out.println(
                "Computed ECDH with invalid parameters" + tc + " shared:" + sharedSecret);
            errors++;
          } else if (!expectedSharedSecret.equals(sharedSecret)) {
            System.out.println(
                "Incorrect ECDH computation"
                    + tc
                    + "\nshared secret:"
                    + sharedSecret
                    + "\nexpected shared secret:"
                    + expectedSharedSecret);
            errors++;
          } else {
            passedTests++;
          }
        } catch (NoSuchAlgorithmException ex) {
          // When the curve is not implemented, this is the expected exception.
          if (result.equals("valid")) {
            skippedTests++;
          } else {
            rejectedTests++;
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.println("Test vector with tcID:" + tc + " throws:" + ex.toString());
            errors++;
          } else {
            rejectedTests++;
          }
        } catch (Exception ex) {
          // Other exceptions typically indicate that something is wrong with the implementation.
          System.out.println("Test vector with tcID:" + tc + " throws:" + ex.toString());
          errors++;
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, passedTests + rejectedTests + skippedTests);
  }
}
