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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link X25519}. */
@RunWith(JUnit4.class)
public final class X25519Test {
  /** Iteration test in Section 5.2 of RFC 7748. https://tools.ietf.org/html/rfc7748 */
  @Test
  public void testComputeSharedSecretWithRfcIteration() throws Exception {
    byte[] k = new byte[32];
    k[0] = 9;
    byte[] prevK = k;
    k = X25519.computeSharedSecret(k, prevK);
    assertEquals(
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", TestUtil.hexEncode(k));
    for (int i = 0; i < 999; i++) {
      byte[] tmp = k;
      k = X25519.computeSharedSecret(k, prevK);
      prevK = tmp;
    }
    assertEquals(
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", TestUtil.hexEncode(k));
    // Omitting 1M iteration to limit the test runtime.
  }

  /**
   * Tests against the test vectors in Section 6.1 of RFC 7748. https://tools.ietf.org/html/rfc7748
   */
  @Test
  public void testPublicFromPrivateWithRfcTestVectors() throws Exception {
    byte[] out =
        X25519.publicFromPrivate(
            TestUtil.hexDecode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    assertEquals(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        TestUtil.hexEncode(out));

    out =
        X25519.publicFromPrivate(
            TestUtil.hexDecode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    assertEquals(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        TestUtil.hexEncode(out));
  }

  @Test
  public void testGeneratePrivateKeyReturnsIntentionallyMalformedKeys() {
    byte[] privateKey = X25519.generatePrivateKey();
    assertEquals(7, privateKey[0] & 7);
    assertEquals(128, privateKey[31] & 192);
  }

  private static void x25519Helper(int privateKeyLen, int peersPublicValueLen)
      throws GeneralSecurityException {
    byte[] privateKey = new byte[privateKeyLen];
    byte[] base = new byte[peersPublicValueLen];
    base[0] = 9;
    try {
      X25519.computeSharedSecret(privateKey, base);
      fail("Expected InvalidKeyException");
    } catch (InvalidKeyException expected) {
    }
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPrivateKeySizeIsLessThan32Bytes()
      throws Exception {
    x25519Helper(31, 32);
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPrivateKeySizeIsGreaterThan32Bytes()
      throws Exception {
    x25519Helper(33, 32);
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPeersPublicValueIsLessThan32Bytes()
      throws Exception {
    x25519Helper(32, 31);
  }

  @Test
  public void testX25519ThrowsIllegalArgExceptionWhenPeersPublicValueIsGreaterThan32Bytes()
      throws Exception {
    x25519Helper(32, 33);
  }

  private static void publicFromPrivateHelper(int privateKeyLen) {
    byte[] privateKey = new byte[privateKeyLen];
    try {
      X25519.publicFromPrivate(privateKey);
      fail("Expected InvalidKeyException");
    } catch (InvalidKeyException expected) {
    }
  }

  @Test
  public void testX25519PublicFromPrivateThrowsIllegalArgExWhenPrivateKeyIsLessThan32Bytes() {
    publicFromPrivateHelper(31);
  }

  @Test
  public void testX25519PublicFromPrivateThrowsIllegalArgExWhenPrivateKeyIsGreaterThan32Bytes() {
    publicFromPrivateHelper(33);
  }

  @Test
  public void testComputeSharedSecretWithWycheproofVectors() throws Exception {
    JSONObject json = WycheproofTestUtil.readJson("testdata/wycheproof/x25519_test.json");
    WycheproofTestUtil.checkAlgAndVersion(json, "X25519", "0.1.3");
    int numTests = json.getInt("numberOfTests");
    // The number of test vectors where the expected and actual shared secret match.
    int passedTests = 0;
    // The number of test vectors where X25519 rejected the input values for a valid reason. These
    // are test vectors where the field "result" is either "acceptable" or "invalid".
    int rejectedTests = 0;
    // The number of test vectors where X25519 computes the wrong shared secret and accepts invalid
    // key.
    int errors = 0;
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        int tcid = testcase.getInt("tcId");
        String comment = testcase.getString("comment");
        String tc = "tcId: " + tcid + " " + comment;
        String result = testcase.getString("result");
        String hexPubKey = testcase.getString("public");
        String hexPrivKey = testcase.getString("private");
        String expectedSharedSecret = testcase.getString("shared");
        String curve = testcase.getString("curve");
        if (!curve.equals("curve25519")) {
          System.out.println("Unknown curve name: " + curve);
          passedTests++;
          continue;
        }
        try {
          String sharedSecret =
              Hex.encode(X25519.computeSharedSecret(Hex.decode(hexPrivKey), Hex.decode(hexPubKey)));
          if (result.equals("invalid")) {
            System.out.println(
                "Computed X25519 with invalid parameters" + tc + " shared:" + sharedSecret);
            errors++;
          } else if (!expectedSharedSecret.equals(sharedSecret)) {
            System.out.println(
                "Incorrect X25519's ECDH computation"
                    + tc
                    + "\nshared secret:"
                    + sharedSecret
                    + "\nexpected shared secret:"
                    + expectedSharedSecret);
            errors++;
          } else {
            passedTests++;
          }
        } catch (InvalidKeyException ex) {
          if (result.equals("valid")) {
            System.out.println("Test vector with tcId: " + tc + " throws:" + ex.toString());
            errors++;
          } else {
            rejectedTests++;
          }
        }
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, passedTests + rejectedTests);
  }
}
