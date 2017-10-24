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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for EcdsaVerifyJce. */
@RunWith(JUnit4.class)
public class EcdsaVerifyJceTest {

  @Test
  public void testWycheproofVectors() throws Exception {
    if (TestUtil.isAndroid()) {
      System.out.println("testWycheproofVectors doesn't work on Android, skipping");
      return;
    }
    JSONObject jsonObj = TestUtil.readJson("../wycheproof/testvectors/ecdsa_test.json");
    WycheproofTestUtil.checkAlgAndVersion(jsonObj, "ECDSA", "0.0a10");
    String algorithm = "ECDSA";
    int numTests = jsonObj.getInt("numberOfTests");
    int cntTests = 0;
    int errors = 0;
    int skippedTests = 0;
    JSONArray testGroups = jsonObj.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);

      KeyFactory kf = KeyFactory.getInstance("EC");
      byte[] encodedPubKey = Hex.decode(group.getString("keyDer"));
      X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encodedPubKey);
      String sha = group.getString("sha");
      String signatureAlgorithm = WycheproofTestUtil.getSignatureAlgorithmName(sha, algorithm);

      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        int tcId = testcase.getInt("tcId");
        // Temporarily skip the following testcases (b/68042214):
        // - Testcase 106 which fails on Kokoro. The next version of Wycheproof test
        //   vectors will change the testcase's result to "acceptable".
        // - Testcase 31 which throws OutOfMemory error in MacOS.
        if (signatureAlgorithm.isEmpty() || tcId == 106 || tcId == 31) {
          skippedTests++;
          continue;
        }
        EcdsaVerifyJce verifier;
        try {
          ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
          verifier = new EcdsaVerifyJce(pubKey, signatureAlgorithm);
        } catch (GeneralSecurityException ignored) {
          // Invalid or unsupported public key.
          skippedTests++;
          continue;
        }
        String tc = "tcId: " + tcId + " " + testcase.getString("comment");
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.getString("sig"));
        String result = testcase.getString("result");
        boolean verified = false;
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
    assertEquals(numTests, cntTests + skippedTests);
  }

  private byte[] getMessage(JSONObject testcase) throws Exception {
    // Previous version of Wycheproof test vectors uses "message" while the new one uses "msg".
    if (testcase.has("msg")) {
      return Hex.decode(testcase.getString("msg"));
    } else {
      return Hex.decode(testcase.getString("message"));
    }
  }

  @Test
  public void testBasic() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    // Sign with JCE's Signature.
    Signature signer = Signature.getInstance("SHA256WithECDSA");
    signer.initSign(priv);
    String message = "Hello";
    signer.update(message.getBytes("UTF-8"));
    byte[] signature = signer.sign();

    // Verify with EcdsaVerifyJce.
    EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, "SHA256WithECDSA");
    try {
      verifier.verify(signature, message.getBytes("UTF-8"));
    } catch (GeneralSecurityException ex) {
      fail("Valid signature, should not throw exception");
    }
  }

  @Test
  public void testBitFlip() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    // Sign with JCE's Signature.
    Signature signer = Signature.getInstance("SHA256WithECDSA");
    signer.initSign(priv);
    String message = "Hello";
    signer.update(message.getBytes("UTF-8"));
    byte[] signature = signer.sign();

    // Verify with EcdsaVerifyJce.
    EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, "SHA256WithECDSA");
    for (int i = 0; i < signature.length; i++) {
      for (int j = 0; j < 8; j++) {
        byte[] modifiedSignature = Arrays.copyOf(signature, signature.length);
        modifiedSignature[i] = (byte) (modifiedSignature[i] ^ (1 << j));
        try {
          verifier.verify(modifiedSignature, message.getBytes("UTF-8"));
          fail("Invalid signature, should have thrown exception");
        } catch (GeneralSecurityException expected) {
          // Expected.
        }
      }
    }
  }
}
