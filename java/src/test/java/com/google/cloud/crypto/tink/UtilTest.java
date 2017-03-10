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

import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.protobuf.TextFormat;
import java.math.BigInteger;
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
  /**
   * Tests that getKeysetInfo doesn't contain key material.
   */
  @Test
  public void testGetKeysetInfo() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =  TestUtil.createKeyset(TestUtil.createKey(
        TestUtil.createHmacKey(keyValue.getBytes("UTF-8"), 16),
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

  // TODO(bleichen): So far I only have points for NIST_P256.
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
  };

  @Test
  public void testPointDecode() throws Exception {
    for (TestVector test : testVector) {
      EllipticCurve curve = Util.getCurveSpec(test.curve).getCurve();
      ECPoint p = Util.ecPointDecode(curve, test.format, test.encoded);
      assertEquals(p.getAffineX(), test.x);
      assertEquals(p.getAffineY(), test.y);
    }
  }

  @Test
  public void testPointEncode() throws Exception {
    for (TestVector test : testVector) {
      EllipticCurve curve = Util.getCurveSpec(test.curve).getCurve();
      ECPoint p = new ECPoint(test.x, test.y);
      byte[] encoded = Util.ecPointEncode(curve, test.format, p);
      assertEquals(TestUtil.hexEncode(encoded), TestUtil.hexEncode(test.encoded));
    }
  }

  // TODO(thaidn): add tests for other functions.
}
