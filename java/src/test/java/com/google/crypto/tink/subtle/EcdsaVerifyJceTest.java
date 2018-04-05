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
    testWycheproofVectors("../wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json");
    testWycheproofVectors("../wycheproof/testvectors/ecdsa_secp384r1_sha384_test.json");
    // https://b.corp.google.com/issues/74209208#comment10
    // testWycheproofVectors("../wycheproof/testvectors/ecdsa_secp384r1_sha512_test.json");
    testWycheproofVectors("../wycheproof/testvectors/ecdsa_secp521r1_sha512_test.json");
  }

  private static void testWycheproofVectors(String fileName) throws Exception {
    JSONObject jsonObj = WycheproofTestUtil.readJson(fileName);

    int errors = 0;
    int cntSkippedTests = 0;
    JSONArray testGroups = jsonObj.getJSONArray("testGroups");
    for (int i = 0; i < testGroups.length(); i++) {
      JSONObject group = testGroups.getJSONObject(i);

      KeyFactory kf = KeyFactory.getInstance("EC");
      byte[] encodedPubKey = Hex.decode(group.getString("keyDer"));
      X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encodedPubKey);
      String sha = group.getString("sha");
      String signatureAlgorithm = WycheproofTestUtil.getSignatureAlgorithmName(sha, "ECDSA");

      JSONArray tests = group.getJSONArray("tests");
      for (int j = 0; j < tests.length(); j++) {
        JSONObject testcase = tests.getJSONObject(j);
        String tcId =
            String.format(
                "testcase %d (%s)", testcase.getInt("tcId"), testcase.getString("comment"));

        if (signatureAlgorithm.isEmpty()) {
          System.out.printf("Skipping %s because signature algorithm is empty", tcId);
          cntSkippedTests++;
          continue;
        }
        EcdsaVerifyJce verifier;
        try {
          ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
          verifier = new EcdsaVerifyJce(pubKey, signatureAlgorithm);
        } catch (GeneralSecurityException ignored) {
          // Invalid or unsupported public key.
          System.out.printf("Skipping %s, exception: %s", tcId, ignored);
          cntSkippedTests++;
          continue;
        }
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.getString("sig"));
        String result = testcase.getString("result");
        try {
          verifier.verify(sig, msg);
          if (result.equals("invalid")) {
            System.out.printf("FAIL %s: accepting invalid signature%n", tcId);
            errors++;
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.printf("FAIL %s: rejecting valid signature, exception: %s%n", tcId, ex);
            errors++;
          }
        }
      }
    }
    System.out.printf("Number of tests skipped: %d", cntSkippedTests);
    assertEquals(0, errors);
  }

  private static byte[] getMessage(JSONObject testcase) throws Exception {
    // Previous version of Wycheproof test vectors uses "message" while the new one uses "msg".
    if (testcase.has("msg")) {
      return Hex.decode(testcase.getString("msg"));
    } else {
      return Hex.decode(testcase.getString("message"));
    }
  }

  @Test
  public void testBasic() throws Exception {
    testBasic(EllipticCurves.getNistP256Params(), "SHA256WithECDSA");
    testBasic(EllipticCurves.getNistP384Params(), "SHA384WithECDSA");
    testBasic(EllipticCurves.getNistP384Params(), "SHA512WithECDSA");
    testBasic(EllipticCurves.getNistP521Params(), "SHA512WithECDSA");
  }

  private static void testBasic(ECParameterSpec ecParams, String algo) throws Exception {
    for (int i = 0; i < 100; i++) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(ecParams);
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

      // Sign with JCE's Signature.
      Signature signer = Signature.getInstance(algo);
      signer.initSign(priv);
      String message = "Hello";
      signer.update(message.getBytes("UTF-8"));
      byte[] signature = signer.sign();

      // Verify with EcdsaVerifyJce.
      EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, algo);
      verifier.verify(signature, message.getBytes("UTF-8"));
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
