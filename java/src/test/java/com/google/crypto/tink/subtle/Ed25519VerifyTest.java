package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Ed25519Verify}.
 *
 * <p>TODO(quannguyen): Use Github Wycheproof's test vectors once it's available (b/66825199).
 */
@RunWith(JUnit4.class)
public final class Ed25519VerifyTest {
  @Test
  public void testVerificationWithPublicKeyLengthDifferentFrom32Byte() throws Exception {
    try {
      Ed25519Verify unused = new Ed25519Verify(new byte[31]);
      fail("Public key length should be 32-byte");
    } catch (IllegalArgumentException expected) {
    }
    try {
      Ed25519Verify unused = new Ed25519Verify(new byte[33]);
      fail("Public key length should be 32-byte");
    } catch (IllegalArgumentException expected) {
    }
  }

  @Test
  public void testVerificationWithWycheproofVectors() throws Exception {
    JSONObject json = TestUtil.readJson("testdata/wycheproof/eddsa_test.json");
    checkAlgAndVersion(json);
    int numTests = json.getInt("numberOfTests");
    int cntTests = 0;
    int errors = 0;
    JSONArray testGroups = json.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);
      JSONObject key = group.getJSONObject("key");
      byte[] publicKey = Hex.decode(key.getString("pk"));
      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        int tcId = testcase.getInt("tcId");
        String tc = "tcId: " + tcId + " " + testcase.getString("comment");
        byte[] msg = Hex.decode(testcase.getString("message"));
        byte[] sig = Hex.decode(testcase.getString("sig"));
        String result = testcase.getString("result");
        boolean verified = false;
        Ed25519Verify verifier = new Ed25519Verify(publicKey);
        try {
          verifier.verify(sig, msg);
          verified = true;
        } catch (GeneralSecurityException ex) {
          verified = false;
          tc += " exception: " + ex;
        }
        if (!verified && result.equals("valid")) {
          System.out.println("Valid signature not verified, testcase : " + tc);
          errors++;
        } else if (verified && result.equals("invalid")) {
          System.out.println("Invalid signature verified, testcase: " + tc);
          errors++;
        }
        cntTests++;
      }
    }
    assertEquals(0, errors);
    assertEquals(numTests, cntTests);
  }

  private void checkAlgAndVersion(JSONObject jsonObj) {
    final String expectedAlgorithm = "EDDSA";
    String algorithm = jsonObj.getString("algorithm");
    if (!expectedAlgorithm.equals(algorithm)) {
      System.out.println("expect algorithm " + expectedAlgorithm + ", got" + algorithm);
    }
    final String expectedVersion = "0.0a18";
    String generatorVersion = jsonObj.getString("generatorVersion");
    if (!generatorVersion.equals(expectedVersion)) {
      System.out.println(
          "expect test vectors with version "
              + expectedVersion
              + " ,got vectors with version "
              + generatorVersion);
    }
  }
}
