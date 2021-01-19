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
package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
//

/** Unit tests for JwtRsaSsaPkcs1Sign and JwtRsaSsaPkcs1Verify. */
@RunWith(JUnitParamsRunner.class)
public class JwtRsaSsaPkcs1SignVerifyTest {

  private RSAPublicKey pub;
  private RSAPrivateCrtKey priv;

  private final void setup(int keySize) throws GeneralSecurityException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(keySize);
    KeyPair keyPair = keyGen.generateKeyPair();
    pub = (RSAPublicKey) keyPair.getPublic();
    priv = (RSAPrivateCrtKey) keyPair.getPrivate();
  }

  private static Object[] parametersAlgoAndSizes() {
    return new Object[] {
      new Object[] {"RS256", 2048},
      new Object[] {"RS256", 3072},
      new Object[] {"RS256", 4098},
      new Object[] {"RS384", 2048},
      new Object[] {"RS384", 3072},
      new Object[] {"RS512", 3072},
      new Object[] {"RS512", 4098},
    };
  }

  private static Object[] parametersSignatures() {
    return new Object[] {"RS256", "RS384", "RS512"};
  }

  private static Object[] parametersKeySizes() {
    return new Object[] {2048, 3072, 4098};
  }

  @Test
  @Parameters(method = "parametersAlgoAndSizes")
  public void testSignVerify_ok(String algorithm, int keySize) throws Exception {
    setup(keySize);
    JwtRsaSsaPkcs1Sign signer = new JwtRsaSsaPkcs1Sign(priv, algorithm);
    JwtRsaSsaPkcs1Verify verifier = new JwtRsaSsaPkcs1Verify(pub, algorithm);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    verifier.verify(signer.sign(token), validator);
  }

  @Test
  @Parameters(method = "parametersKeySizes")
  public void testSignVerify_wrongSignerAlgo_throw(int keySize) throws Exception {
    setup(keySize);
    assertThrows(
        GeneralSecurityException.class,
        () -> new JwtRsaSsaPkcs1Sign(priv, "unknown"));
  }

  @Test
  @Parameters(method = "parametersKeySizes")
  public void testSignVerify_wrongVerifierAlgo_throw(int keySize) throws Exception {
    setup(keySize);
    assertThrows(
        GeneralSecurityException.class,
        () -> new JwtRsaSsaPkcs1Verify(pub, "unknown"));
  }

  private static Object[] parametersForTestSignVerify_algoMismatch_throw() {
    return new Object[] {
      new Object[] {"RS256", "RS384", 2048},
      new Object[] {"RS256", "RS512", 2048},
      new Object[] {"RS384", "RS256", 2048},
      new Object[] {"RS384", "RS512", 2048},
      new Object[] {"RS512", "RS256", 2048},
      new Object[] {"RS512", "RS384", 2048},
      new Object[] {"RS256", "RS384", 3072},
      new Object[] {"RS256", "RS512", 3072},
      new Object[] {"RS384", "RS256", 3072},
      new Object[] {"RS384", "RS512", 3072},
      new Object[] {"RS512", "RS256", 3072},
      new Object[] {"RS512", "RS384", 3072},
      new Object[] {"RS256", "RS384", 4096},
      new Object[] {"RS256", "RS512", 4096},
      new Object[] {"RS384", "RS256", 4096},
      new Object[] {"RS384", "RS512", 4096},
      new Object[] {"RS512", "RS256", 4096},
      new Object[] {"RS512", "RS384", 4096},
    };
  }

  @Test
  @Parameters
  public void testSignVerify_algoMismatch_throw(
      String signerAlgo, String verifierAlgo, int keySize)
      throws Exception {
    setup(keySize);
    JwtRsaSsaPkcs1Sign signer = new JwtRsaSsaPkcs1Sign(priv, signerAlgo);
    JwtRsaSsaPkcs1Verify verifier = new JwtRsaSsaPkcs1Verify(pub, verifierAlgo);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verify(signer.sign(token), validator));
  }

  @Test
  @Parameters(method = "parametersAlgoAndSizes")
  public void testSignVerifyDifferentKey_throw(String algo, int keySize)
      throws Exception {
    setup(keySize);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    KeyPair otherKeyPair = keyGen.generateKeyPair();
    RSAPublicKey otherPub = (RSAPublicKey) otherKeyPair.getPublic();
    JwtRsaSsaPkcs1Sign signer = new JwtRsaSsaPkcs1Sign(priv, algo);
    JwtRsaSsaPkcs1Verify verifier = new JwtRsaSsaPkcs1Verify(otherPub, algo);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verify(signer.sign(token), validator));
  }

  @Test
  @Parameters(method = "parametersAlgoAndSizes")
  public void testSignVerifyNonAScii_throw(String algo, int keySize)
      throws Exception {
    setup(keySize);
    JwtRsaSsaPkcs1Sign signer = new JwtRsaSsaPkcs1Sign(priv, algo);
    JwtRsaSsaPkcs1Verify verifier = new JwtRsaSsaPkcs1Verify(pub, algo);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    String result = signer.sign(token);
    char[] validJwt = new char[result.length()];
    for (int j = 0; j < result.length(); j++) {
      validJwt[j] = result.charAt(j);
    }

    for (int i = 0; i < result.length() - 1; ++i) {
      char[] nonASciiJwt = Arrays.copyOf(validJwt, result.length());
      assertThat(validJwt[i] & 0x80).isSameInstanceAs(0);
      nonASciiJwt[i] = (char) (validJwt[i] | 0x80);
      assertThrows(
          JwtInvalidException.class,
          () -> verifier.verify(new String(nonASciiJwt), validator));
    }
  }

  @Test
  @Parameters(method = "parametersAlgoAndSizes")
  public void testSignVerify_bitFlipped_throw(String algo, int keySize)
      throws Exception {
    setup(keySize);
    JwtRsaSsaPkcs1Sign signer = new JwtRsaSsaPkcs1Sign(priv, algo);
    JwtRsaSsaPkcs1Verify verifier = new JwtRsaSsaPkcs1Verify(pub, algo);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    String result = signer.sign(token);
    char[] validJwt = new char[result.length()];
    for (int j = 0; j < result.length(); j++) {
      validJwt[j] = result.charAt(j);
    }

    // We ignore the last byte because the bas64 decoder ignores some of the bits.
    for (int i = 0; i < result.length() - 1; ++i) {
      // Flip every bit of i-th byte.
      for (int b = 0; b < 8; ++b) {
        char[] invalidJwt = Arrays.copyOf(validJwt, result.length());
        invalidJwt[i] = (char) (validJwt[i] ^ (1 << b));
        assertThrows(
            GeneralSecurityException.class,
            () -> verifier.verify(new String(invalidJwt), validator));
      }
    }
  }

  @Test
  @Parameters(method = "parametersSignatures")
  public void testSignVerify_smallKeySign_throw(String algo) throws Exception {
    setup(1024);
    assertThrows(
        GeneralSecurityException.class,
        () -> new JwtRsaSsaPkcs1Sign(priv, algo));

  }

  @Test
  @Parameters(method = "parametersSignatures")
  public void testSignVerify_smallKeyVerify_throw(String algo) throws Exception {
    setup(1024);
    assertThrows(
        GeneralSecurityException.class,
        () -> new JwtRsaSsaPkcs1Verify(pub, algo));

  }

  @Test
  public void badHeader_verificationFails() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();

    // Construct a token with a valid Signature, but with an invalid header.
    RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(
        (RSAPrivateCrtKey) keyPair.getPrivate(), JwtSigUtil.hashForPkcs1Algorithm("RS256"));
    RawJwt emptyRawJwt = new RawJwt.Builder().build();
    JSONObject wrongTypeHeader = new JSONObject();
    wrongTypeHeader.put("alg", "RS256");
    wrongTypeHeader.put("typ", "IWT");  // bad type
    String headerStr = Base64.urlSafeEncode(wrongTypeHeader.toString().getBytes(UTF_8));
    String payloadStr = JwtFormat.encodePayload(emptyRawJwt.getPayload());
    String unsignedCompact = headerStr + "." + payloadStr;
    String tag = JwtFormat.encodeSignature(signer.sign(unsignedCompact.getBytes(US_ASCII)));
    String signedCompact = unsignedCompact + "." + tag;

    JwtRsaSsaPkcs1Verify verifier = new JwtRsaSsaPkcs1Verify(
        (RSAPublicKey) keyPair.getPublic(), "RS256");
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        JwtInvalidException.class,
        () -> verifier.verify(signedCompact, validator));
  }
}
