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
import com.google.crypto.tink.TestUtil.BytesMutation;
import com.google.crypto.tink.WycheproofTestUtil;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
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
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json", EcdsaEncoding.DER);
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp384r1_sha512_test.json", EcdsaEncoding.DER);
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp521r1_sha512_test.json", EcdsaEncoding.DER);
  }

  private static void testWycheproofVectors(String fileName, EcdsaEncoding encoding)
      throws Exception {
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
          System.out.printf("Skipping %s because signature algorithm is empty\n", tcId);
          cntSkippedTests++;
          continue;
        }
        EcdsaVerifyJce verifier;
        try {
          ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(x509keySpec);
          HashType hash = WycheproofTestUtil.getHashType(sha);
          verifier = new EcdsaVerifyJce(pubKey, hash, encoding);
        } catch (GeneralSecurityException ignored) {
          // Invalid or unsupported public key.
          System.out.printf("Skipping %s, exception: %s\n", tcId, ignored);
          cntSkippedTests++;
          continue;
        }
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.getString("sig"));
        String result = testcase.getString("result");
        try {
          verifier.verify(sig, msg);
          if (result.equals("invalid")) {
            System.out.printf("FAIL %s: accepting invalid signature\n", tcId);
            errors++;
          }
        } catch (GeneralSecurityException ex) {
          if (result.equals("valid")) {
            System.out.printf("FAIL %s: rejecting valid signature, exception: %s\n", tcId, ex);
            errors++;
          }
        }
      }
    }
    System.out.printf("Number of tests skipped: %d\n", cntSkippedTests);
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
  public void testConstrutorExceptions() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    // Verify with EcdsaVerifyJce.
    try {
      new EcdsaVerifyJce(pub, HashType.SHA1, EcdsaEncoding.DER);
      fail("Unsafe hash, should have thrown exception.");
    } catch (GeneralSecurityException e) {
      // Expected.
      TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
    }
  }

  @Test
  public void testBasic() throws Exception {
    testAgainstJceSignatureInstance(EllipticCurves.getNistP256Params(), HashType.SHA256);
    testAgainstJceSignatureInstance(EllipticCurves.getNistP384Params(), HashType.SHA512);
    testAgainstJceSignatureInstance(EllipticCurves.getNistP521Params(), HashType.SHA512);
    testSignVerify(EllipticCurves.getNistP256Params(), HashType.SHA256);
    testSignVerify(EllipticCurves.getNistP384Params(), HashType.SHA512);
    testSignVerify(EllipticCurves.getNistP521Params(), HashType.SHA512);
  }

  private static void testAgainstJceSignatureInstance(ECParameterSpec ecParams, HashType hash)
      throws Exception {
    for (int i = 0; i < 100; i++) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(ecParams);
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

      // Sign with JCE's Signature.
      Signature signer = Signature.getInstance(SubtleUtil.toEcdsaAlgo(hash));
      signer.initSign(priv);
      String message = "Hello";
      signer.update(message.getBytes("UTF-8"));
      byte[] signature = signer.sign();

      // Verify with EcdsaVerifyJce.
      EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, hash, EcdsaEncoding.DER);
      verifier.verify(signature, message.getBytes("UTF-8"));
    }
  }

  private static void testSignVerify(ECParameterSpec ecParams, HashType hash) throws Exception {
    for (int i = 0; i < 100; i++) {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(ecParams);
      KeyPair keyPair = keyGen.generateKeyPair();
      ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
      ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

      EcdsaEncoding[] encodings = new EcdsaEncoding[] {EcdsaEncoding.IEEE_P1363, EcdsaEncoding.DER};
      for (EcdsaEncoding encoding : encodings) {
        // Sign with EcdsaSignJce
        EcdsaSignJce signer = new EcdsaSignJce(priv, hash, encoding);

        byte[] message = "Hello".getBytes("UTF-8");
        byte[] signature = signer.sign(message);

        // Verify with EcdsaVerifyJce.
        EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, hash, encoding);
        verifier.verify(signature, message);
      }
    }
  }

  @Test
  public void testModification() throws Exception {
    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();

    EcdsaEncoding[] encodings = new EcdsaEncoding[] {EcdsaEncoding.IEEE_P1363, EcdsaEncoding.DER};
    for (EcdsaEncoding encoding : encodings) {
      // Sign with EcdsaSignJce
      EcdsaSignJce signer = new EcdsaSignJce(priv, HashType.SHA256, encoding);
      byte[] message = "Hello".getBytes("UTF-8");
      byte[] signature = signer.sign(message);

      // Verify with EcdsaVerifyJce.
      EcdsaVerifyJce verifier = new EcdsaVerifyJce(pub, HashType.SHA256, encoding);

      for (BytesMutation mutation : TestUtil.generateMutations(signature)) {
        try {
          verifier.verify(mutation.value, message);
          fail(
              String.format(
                  "Invalid signature, should have thrown exception : signature = %s, message = %s, "
                      + " description = %s",
                  Hex.encode(mutation.value), message, mutation.description));
        } catch (GeneralSecurityException expected) {
          // Expected.
        }
      }

      // Encodings mismatch.
      verifier =
          new EcdsaVerifyJce(
              pub,
              HashType.SHA256,
              encoding == EcdsaEncoding.IEEE_P1363 ? EcdsaEncoding.DER : EcdsaEncoding.IEEE_P1363);
      try {
        verifier.verify(signature, message);
        fail("Invalid signature, should have thrown exception");
      } catch (GeneralSecurityException expected) {
        // Expected.
      }
    }
  }
}
