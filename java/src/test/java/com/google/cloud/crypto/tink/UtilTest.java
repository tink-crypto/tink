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

package com.google.cloud.crypto.tink;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.EcUtil;
import com.google.protobuf.TextFormat;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Util.
 */
@RunWith(JUnit4.class)
public class UtilTest {
  @Test
  public void testValidateKeyset() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =  TestUtil.createKeyset(TestUtil.createKey(
        TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK));
    try {
      Util.validateKeyset(keyset);
    } catch (GeneralSecurityException e) {
      fail("Valid keyset; should not throw Exception: " + e);
    }

    // Empty keyset.
    try {
      Util.validateKeyset(Keyset.newBuilder().build());
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("empty keyset"));
    }

    // Primary key is disabled.
    Keyset invalidKeyset = TestUtil.createKeyset(TestUtil.createKey(
        TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
        42,
        KeyStatusType.DISABLED,
        OutputPrefixType.TINK));
    try {
      Util.validateKeyset(invalidKeyset);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("keyset doesn't contain a valid primary key"));
    }

    // Multiple primary keys.
    invalidKeyset = TestUtil.createKeyset(
        TestUtil.createKey(
            TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK),
        TestUtil.createKey(
            TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK)
    );
    try {
      Util.validateKeyset(invalidKeyset);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("keyset contains multiple primary keys"));
    }
  }

  /**
   * Tests that getKeysetInfo doesn't contain key material.
   */
  @Test
  public void testGetKeysetInfo() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =  TestUtil.createKeyset(TestUtil.createKey(
        TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.TINK));
    assertTrue(TextFormat.printToUnicodeString(keyset).contains(keyValue));

    KeysetInfo keysetInfo = Util.getKeysetInfo(keyset);
    assertFalse(TextFormat.printToUnicodeString(keysetInfo).contains(keyValue));
  }

  /**
   * A class for storing test vectors.
   * This class contains the directory for the public and private key,
   * the message and the corresponding signature.
   */
  protected static class TestVector {
    protected EllipticCurveType curve;
    protected EcPointFormat format;
    protected byte[] encoded;
    BigInteger x;
    BigInteger y;

    protected TestVector(
        EllipticCurveType curve,
        EcPointFormat format,
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

  protected static TestVector[] testVector = {
    // NIST_P256
    new TestVector(
        EllipticCurveType.NIST_P256,
        EcPointFormat.UNCOMPRESSED,
        "04"
            + "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a"
            + "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    new TestVector(
        EllipticCurveType.NIST_P256,
        EcPointFormat.COMPRESSED,
        "03b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a",
        "79974177209371530366349631093481213364328002500948308276357601809416549347930",
        "11093679777528052772423074391650378811758820120351664471899251711300542565879"),
    // Exceptional point: x==0
    new TestVector(
        EllipticCurveType.NIST_P256,
        EcPointFormat.UNCOMPRESSED,
        "04"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    new TestVector(
        EllipticCurveType.NIST_P256,
        EcPointFormat.COMPRESSED,
        "020000000000000000000000000000000000000000000000000000000000000000",
        "0",
        "46263761741508638697010950048709651021688891777877937875096931459006746039284"),
    // Exceptional point: x==-3
    new TestVector(
        EllipticCurveType.NIST_P256,
        EcPointFormat.UNCOMPRESSED,
        "04"
            + "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
            + "19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    new TestVector(
        EllipticCurveType.NIST_P256,
        EcPointFormat.COMPRESSED,
        "03ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        "11508551065151498768481026661199445482476508121209842448718573150489103679777"),
    // NIST_P384
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.UNCOMPRESSED,
        "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a"
            + "385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc"
            + "29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e"
            + "5f",
        "2624703509579968926862315674456698189185292349110921338781561590"
            + "0925518854738050089022388053975719786650872476732087",
        "8325710961489029985546751289520108179287853048861315594709205902"
            + "480503199884419224438643760392947333078086511627871"),
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.COMPRESSED,
        "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a"
            + "385502f25dbf55296c3a545e3872760ab7",
        "2624703509579968926862315674456698189185292349110921338781561590"
            + "0925518854738050089022388053975719786650872476732087",
        "8325710961489029985546751289520108179287853048861315594709205902"
            + "480503199884419224438643760392947333078086511627871"),
    // x = 0
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "00000000000000000000000000000000003cf99ef04f51a5ea630ba3f9f960dd"
            + "593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e52"
            + "1e",
        "0",
        "9384923975005507693384933751151973636103286582194273515051780595"
            + "652610803541482195894618304099771370981414591681054"),
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.COMPRESSED,
        "0200000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000",
        "0",
        "9384923975005507693384933751151973636103286582194273515051780595"
            + "652610803541482195894618304099771370981414591681054"),
    // x = 2
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000002732152442fb6ee5c3e6ce1d920c059"
            + "bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfd"
            + "b3",
        "2",
        "1772015366480916228638409476801818679957736647795608728422858375"
            + "4887974043472116432532980617621641492831213601947059"),
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000002",
        "2",
        "1772015366480916228638409476801818679957736647795608728422858375"
            + "4887974043472116432532980617621641492831213601947059"),
    // x = -3
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.UNCOMPRESSED,
        "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "feffffffff0000000000000000fffffffc2de9de09a95b74e6b2c430363e1afb"
            + "8dff7164987a8cfe0a0d5139250ac02f797f81092a9bdc0e09b574a8f43bf80c"
            + "17",
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112316",
        "7066741234775658874139271223692271325950306561732202191471600407"
            + "582071247913794644254895122656050391930754095909911"),
    new TestVector(
        EllipticCurveType.NIST_P384,
        EcPointFormat.COMPRESSED,
        "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "feffffffff0000000000000000fffffffc",
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112316",
        "7066741234775658874139271223692271325950306561732202191471600407"
            + "582071247913794644254895122656050391930754095909911"),
    // NIST_P521
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.UNCOMPRESSED,
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
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.COMPRESSED,
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
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "00000000d20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896f"
            + "ee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440"
            + "ae001f4f87",
        "0",
        "2816414230262626695230339754503506208598534788872316917808418392"
            + "0894686826982898181454171638541149642517061885689521392260532032"
            + "30035588176689756661142736775"),
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000000",
        "0",
        "2816414230262626695230339754503506208598534788872316917808418392"
            + "0894686826982898181454171638541149642517061885689521392260532032"
            + "30035588176689756661142736775"),
    // x = 1
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "0000010010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03d"
            + "f47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c"
            + "832e843564",
        "1",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.COMPRESSED,
        "0200000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000001",
        "1",
        "2265505274322546447629271557184988697103589068170534253193208655"
            + "0778100463909972583865730916407864371153050622267306901033104806"
            + "9570407113457901669103973732"),
    // x = 2
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.UNCOMPRESSED,
        "0400000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "00000200d9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7f"
            + "ce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051"
            + "d6aa505acf",
        "2",
        "2911448509017565583245824537994174021964465504209366849707937264"
            + "0417919148200722009442607963590225526059407040161685364728526719"
            + "10134103604091376779754756815"),
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.COMPRESSED,
        "0300000000000000000000000000000000000000000000000000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000002",
        "2",
        "2911448509017565583245824537994174021964465504209366849707937264"
            + "0417919148200722009442607963590225526059407040161685364728526719"
            + "10134103604091376779754756815"),
    // x = -2
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.UNCOMPRESSED,
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
    new TestVector(
        EllipticCurveType.NIST_P521,
        EcPointFormat.COMPRESSED,
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
    for (TestVector test : testVector) {
      EllipticCurve curve = Util.getCurveSpec(test.curve).getCurve();
      ECPoint p = EcUtil.ecPointDecode(curve, Util.getPointFormat(test.format), test.encoded);
      assertEquals(p.getAffineX(), test.x);
      assertEquals(p.getAffineY(), test.y);
    }
  }

  @Test
  public void testPointEncode() throws Exception {
    for (TestVector test : testVector) {
      EllipticCurve curve = Util.getCurveSpec(test.curve).getCurve();
      ECPoint p = new ECPoint(test.x, test.y);
      byte[] encoded = EcUtil.ecPointEncode(curve, Util.getPointFormat(test.format), p);
      assertEquals(TestUtil.hexEncode(encoded), TestUtil.hexEncode(test.encoded));
    }
  }

  // TODO(thaidn): add tests for other functions.
}
