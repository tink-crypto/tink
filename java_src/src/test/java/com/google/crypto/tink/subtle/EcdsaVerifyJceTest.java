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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.BytesMutation;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for EcdsaVerifyJce. */
@RunWith(JUnit4.class)
public class EcdsaVerifyJceTest {

  @Before
  public void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test ECDSA verify in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json", EcdsaEncoding.DER);
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp384r1_sha512_test.json", EcdsaEncoding.DER);
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp521r1_sha512_test.json", EcdsaEncoding.DER);
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp256r1_sha256_p1363_test.json",
        EcdsaEncoding.IEEE_P1363);
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp384r1_sha512_p1363_test.json",
        EcdsaEncoding.IEEE_P1363);
    testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp521r1_sha512_p1363_test.json",
        EcdsaEncoding.IEEE_P1363);
  }

  private static void testWycheproofVectors(String fileName, EcdsaEncoding encoding)
      throws Exception {
    JsonObject jsonObj = WycheproofTestUtil.readJson(fileName);

    int errors = 0;
    int cntSkippedTests = 0;
    JsonArray testGroups = jsonObj.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();

      KeyFactory kf = KeyFactory.getInstance("EC");
      byte[] encodedPubKey = Hex.decode(group.get("keyDer").getAsString());
      X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encodedPubKey);
      String sha = group.get("sha").getAsString();
      String signatureAlgorithm = WycheproofTestUtil.getSignatureAlgorithmName(sha, "ECDSA");

      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        String tcId =
            String.format("testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());

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
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
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

  private static byte[] getMessage(JsonObject testcase) throws Exception {
    // Previous version of Wycheproof test vectors uses "message" while the new one uses "msg".
    if (testcase.has("msg")) {
      return Hex.decode(testcase.get("msg").getAsString());
    } else {
      return Hex.decode(testcase.get("message").getAsString());
    }
  }

  @Test
  public void testConstrutorExceptions() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    ECParameterSpec ecParams = EllipticCurves.getNistP256Params();
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    KeyPair keyPair = keyGen.generateKeyPair();
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    // Verify with EcdsaVerifyJce.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> new EcdsaVerifyJce(pub, HashType.SHA1, EcdsaEncoding.DER));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  @Test
  public void testAgainstJCEInstance256() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    testAgainstJceSignatureInstance(EllipticCurves.getNistP256Params(), HashType.SHA256);
  }

  @Test
  public void testAgainstJCEInstance384() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    testAgainstJceSignatureInstance(EllipticCurves.getNistP384Params(), HashType.SHA512);
  }

  @Test
  public void testAgainstJCEInstance512() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    testAgainstJceSignatureInstance(EllipticCurves.getNistP521Params(), HashType.SHA512);
  }

  @Test
  public void testSignVerify256() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    testSignVerify(EllipticCurves.getNistP256Params(), HashType.SHA256);
  }

  @Test
  public void testSignVerify384() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    testSignVerify(EllipticCurves.getNistP384Params(), HashType.SHA512);
  }

  @Test
  public void testSignVerify512() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());
    testSignVerify(EllipticCurves.getNistP521Params(), HashType.SHA512);
  }

  private static void testAgainstJceSignatureInstance(ECParameterSpec ecParams, HashType hash)
      throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    int numSignatures = 100;
    if (TestUtil.isTsan()) {
      numSignatures = 5;
    }
    for (int i = 0; i < numSignatures; i++) {
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
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    int numSignatures = 100;
    if (TestUtil.isTsan()) {
      numSignatures = 5;
    }
    for (int i = 0; i < numSignatures; i++) {
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
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

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

      for (final BytesMutation mutation : TestUtil.generateMutations(signature)) {
        assertThrows(
            String.format(
                "Invalid signature, should have thrown exception : signature = %s, message = %s, "
                    + " description = %s",
                Hex.encode(mutation.value), Arrays.toString(message), mutation.description),
            GeneralSecurityException.class,
            () -> verifier.verify(mutation.value, message));
      }

      // Encodings mismatch.
      EcdsaVerifyJce verifier2 =
          new EcdsaVerifyJce(
              pub,
              HashType.SHA256,
              encoding == EcdsaEncoding.IEEE_P1363 ? EcdsaEncoding.DER : EcdsaEncoding.IEEE_P1363);
      assertThrows(GeneralSecurityException.class, () -> verifier2.verify(signature, message));
    }
  }

  @Test
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    assertThrows(
        GeneralSecurityException.class,
        () -> testWycheproofVectors(
        "../wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json", EcdsaEncoding.DER));
  }
}
