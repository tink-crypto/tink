// Copyright 2018 Google Inc.
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
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.WycheproofTestUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPkcs1VerifyJce. */
@RunWith(JUnit4.class)
public class RsaSsaPkcs1VerifyJceTest {

  @Before
  public void useConscrypt() throws Exception {
    // If Tink is build in FIPS-only mode, then we register Conscrypt for the tests.
    if (TinkFips.useOnlyFips()) {
      try {
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
      } catch (Throwable cause) {
        throw new IllegalStateException(
            "Cannot test RSA PKCS1.5 verify in FIPS-mode without Conscrypt Provider", cause);
      }
    }
  }

  @Test
  public void testConstructorExceptions() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips()); // Only 3072-bit modulus is supported in FIPS.

    int keySize = 2048;
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    RSAPublicKey pub = (RSAPublicKey) keyGen.generateKeyPair().getPublic();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> new RsaSsaPkcs1VerifyJce(pub, HashType.SHA1));
    TestUtil.assertExceptionContains(e, "Unsupported hash: SHA1");
  }

  @Test
  public void testWycheproofVectors() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips()); // Only 3072-bit modulus is supported in FIPS.

    testWycheproofVectors("../wycheproof/testvectors/rsa_signature_2048_sha256_test.json");
    testWycheproofVectors("../wycheproof/testvectors/rsa_signature_4096_sha512_test.json");
  }

  private static void testWycheproofVectors(String fileName) throws Exception {
    JsonObject jsonObj = WycheproofTestUtil.readJson(fileName);

    int errors = 0;
    JsonArray testGroups = jsonObj.getAsJsonArray("testGroups");
    for (int i = 0; i < testGroups.size(); i++) {
      JsonObject group = testGroups.get(i).getAsJsonObject();

      KeyFactory kf = KeyFactory.getInstance("RSA");
      byte[] encodedPubKey = Hex.decode(group.get("keyDer").getAsString());
      X509EncodedKeySpec x509keySpec = new X509EncodedKeySpec(encodedPubKey);
      String sha = group.get("sha").getAsString();
      HashType hash = WycheproofTestUtil.getHashType(sha);

      JsonArray tests = group.getAsJsonArray("tests");
      for (int j = 0; j < tests.size(); j++) {
        JsonObject testcase = tests.get(j).getAsJsonObject();
        // Do not perform the Wycheproof test if the RSA public exponent is small.
        if (WycheproofTestUtil.checkFlags(testcase, "SmallPublicKey")) {
          continue;
        }
        String tcId =
            String.format(
                "testcase %d (%s)",
                testcase.get("tcId").getAsInt(), testcase.get("comment").getAsString());
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(x509keySpec);

        RsaSsaPkcs1VerifyJce verifier = new RsaSsaPkcs1VerifyJce(pubKey, hash);
        byte[] msg = getMessage(testcase);
        byte[] sig = Hex.decode(testcase.get("sig").getAsString());
        String result = testcase.get("result").getAsString();
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
    assertEquals(0, errors);
  }

  @Test
  public void testWycheproofVectors3072() throws Exception {
    Assume.assumeTrue(!TinkFips.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable());

    testWycheproofVectors("../wycheproof/testvectors/rsa_signature_3072_sha512_test.json");
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
  public void testFailIfFipsModuleNotAvailable() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    assertThrows(
        GeneralSecurityException.class,
        () ->
            testWycheproofVectors(
                "../wycheproof/testvectors/rsa_signature_3072_sha512_test.json"));
  }
}
