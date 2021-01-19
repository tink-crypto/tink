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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for JwtRsaSsaPssSign and JwtRsaSsaPssVerify. */
@RunWith(JUnitParamsRunner.class)
public class JwtEcdsaSignVerifyTest {

  private static Object[] parametersAlgorithms() {
    return new Object[] {"ES256", "ES384", "ES512"};
  }

  private static final ECParameterSpec eCParamSpecsForAlgorithm(String algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case "ES256":
        return EllipticCurves.getNistP256Params();
      case "ES384":
        return EllipticCurves.getNistP384Params();
      case "ES512":
        return EllipticCurves.getNistP521Params();
      default: // fall out
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  private static final KeyPair generateKeyPair(String algorithm) throws GeneralSecurityException {
    ECParameterSpec ecParams = eCParamSpecsForAlgorithm(algorithm);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    return keyGen.generateKeyPair();
  }

  @Test
  @Parameters(method = "parametersAlgorithms")
  public void testSignVerify_ok(String algorithm) throws Exception {
    KeyPair keyPair = generateKeyPair(algorithm);
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    JwtEcdsaSign signer = new JwtEcdsaSign(priv, algorithm);
    JwtEcdsaVerify verifier = new JwtEcdsaVerify(pub, algorithm);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    verifier.verify(signer.sign(token), validator);
  }

  @Test
  @Parameters(method = "parametersAlgorithms")
  public void testSignVerify_wrongSignerAlgo_throw(String algorithm) throws Exception {
    KeyPair keyPair = generateKeyPair(algorithm);
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    assertThrows(GeneralSecurityException.class, () -> new JwtEcdsaSign(priv, "unknown"));
  }

  @Test
  @Parameters(method = "parametersAlgorithms")
  public void testSignVerify_wrongVerifierAlgo_throw(String algorithm) throws Exception {
    KeyPair keyPair = generateKeyPair(algorithm);
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    assertThrows(GeneralSecurityException.class, () -> new JwtEcdsaVerify(pub, "unknown"));
  }

  private static Object[] parametersAlgorithmMismatch() {
    return new Object[] {
      new Object[] {"ES256", "ES384"},
      new Object[] {"ES256", "ES512"},
      new Object[] {"ES384", "ES256"},
      new Object[] {"ES384", "ES512"},
      new Object[] {"ES512", "ES256"},
      new Object[] {"ES512", "ES384"},
      new Object[] {"ES256", "ES384"},
      new Object[] {"ES256", "ES512"},
      new Object[] {"ES384", "ES256"},
      new Object[] {"ES384", "ES512"},
      new Object[] {"ES512", "ES256"},
      new Object[] {"ES512", "ES384"},
      new Object[] {"ES256", "ES384"},
      new Object[] {"ES256", "ES512"},
      new Object[] {"ES384", "ES256"},
      new Object[] {"ES384", "ES512"},
      new Object[] {"ES512", "ES256"},
      new Object[] {"ES512", "ES384"},
    };
  }

  @Test
  @Parameters(method = "parametersAlgorithmMismatch")
  public void testSignVerify_algoSignMismatch_throw(String keyAlgo, String signerAlgo)
      throws Exception {
    KeyPair keyPair = generateKeyPair(keyAlgo);
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    assertThrows(GeneralSecurityException.class, () -> new JwtEcdsaSign(priv, signerAlgo));
  }

  @Test
  @Parameters(method = "parametersAlgorithmMismatch")
  public void testSignVerify_algoVerifyMismatch_throw(String keyAlgo, String verifierAlgo)
      throws Exception {
    KeyPair keyPair = generateKeyPair(keyAlgo);
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    assertThrows(GeneralSecurityException.class, () -> new JwtEcdsaVerify(pub, verifierAlgo));
  }

  @Test
  @Parameters(method = "parametersAlgorithmMismatch")
  public void testSignVerify_algoMismatch_throw(String algorithm, String otherAlgo)
      throws Exception {
    KeyPair keyPair = generateKeyPair(algorithm);
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    JwtEcdsaSign signer = new JwtEcdsaSign(priv, algorithm);
    JwtEcdsaVerify verifier = new JwtEcdsaVerify(pub, algorithm);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    String compactJwt = signer.sign(token);
    String[] parts = compactJwt.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    // Patch the JWT with a different algorithm.
    String headerBase64 =
        Base64.urlSafeEncode(header.replace(algorithm, otherAlgo).getBytes(UTF_8));
    String newToken = headerBase64 + "." + parts[1] + "." + parts[2];
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(newToken, validator));
  }

  @Test
  @Parameters(method = "parametersAlgorithms")
  public void testSignVerifyDifferentKey_throw(String algorithm) throws Exception {
    KeyPair keyPair = generateKeyPair(algorithm);
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    JwtEcdsaSign signer = new JwtEcdsaSign(priv, algorithm);
    KeyPair otherKeyPair = generateKeyPair(algorithm);
    ECPublicKey pub = (ECPublicKey) otherKeyPair.getPublic();
    JwtEcdsaVerify verifier = new JwtEcdsaVerify(pub, algorithm);
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verify(signer.sign(token), validator));
  }

  @Test
  @Parameters(method = "parametersAlgorithms")
  public void testSignVerifyNonAScii_throw(String algorithm) throws Exception {
    KeyPair keyPair = generateKeyPair(algorithm);
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    JwtEcdsaSign signer = new JwtEcdsaSign(priv, algorithm);
    JwtEcdsaVerify verifier = new JwtEcdsaVerify(pub, algorithm);
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
  @Parameters(method = "parametersAlgorithms")
  public void testSignVerify_bitFlipped_throw(String algorithm) throws Exception {
    KeyPair keyPair = generateKeyPair(algorithm);
    ECPublicKey pub = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey priv = (ECPrivateKey) keyPair.getPrivate();
    JwtEcdsaSign signer = new JwtEcdsaSign(priv, algorithm);
    JwtEcdsaVerify verifier = new JwtEcdsaVerify(pub, algorithm);
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
}
