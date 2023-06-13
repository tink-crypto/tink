// Copyright 2023 Google LLC
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

package com.google.crypto.tink.apps.paymentmethodtoken;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtEcdsaPrivateKey;
import com.google.crypto.tink.jwt.JwtEcdsaPublicKey;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;
import com.google.crypto.tink.jwt.VerifiedJwt;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class JwtKeyConverterTest {

  @BeforeClass
  public static void setUp() throws Exception {
    JwtSignatureConfig.register();
  }

  @Test
  public void importAndUseEcP256KeyPairGeneratedUsingOpenSSL_success() throws Exception {
    // Example key pair taken from
    // https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#using-openssl
    String based64EncodedEcNistP256PublicKey =
        "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y=";
    String based64EncodedPkcs8EcNistP256PrivateKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
            + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
            + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";

    // Convert based64EncodedEcNistP256PublicKey to a Tink JWT ECDSA public key.
    JwtEcdsaPublicKey jwtEcdsaPublicKey =
        JwtKeyConverter.fromBase64EncodedNistP256PublicKey(based64EncodedEcNistP256PublicKey);

    // Convert pkcs8PrivateKeyBase64 and jwtEcdsaPublicKey to a Tink JWT ECDSA private key.
    JwtEcdsaPrivateKey jwtEcdsaPrivateKey =
        JwtKeyConverter.fromBased64EncodedPkcs8EcNistP256PrivateKey(
            based64EncodedPkcs8EcNistP256PrivateKey,
            jwtEcdsaPublicKey,
            InsecureSecretKeyAccess.get());

    // Create a JWT token using jwtEcdsaPrivateKey.
    KeysetHandle privateKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtEcdsaPrivateKey).makePrimary().withRandomId())
            .build();
    JwtPublicKeySign signer = privateKeysetHandle.getPrimitive(JwtPublicKeySign.class);
    Clock clock = Clock.systemUTC();
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setTypeHeader("JWT")
            .addStringClaim("merchantOrigin", "www.sub-merchant.com")
            .addStringClaim("merchantId", "platformMerchantId")
            .setIssuedAt(clock.instant())
            .setExpiration(clock.instant().plusSeconds(3600)) // token expires in 1 hour
            .build();
    String token = signer.signAndEncode(rawJwt);

    // Verify the token using jwtEcdsaPublicKey.
    KeysetHandle publicKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(jwtEcdsaPublicKey).makePrimary().withRandomId())
            .build();
    JwtPublicKeyVerify verifer = publicKeysetHandle.getPrimitive(JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().expectTypeHeader("JWT").build();
    VerifiedJwt verifiedJwt = verifer.verifyAndDecode(token, validator);
    assertThat(verifiedJwt.getStringClaim("merchantOrigin")).isEqualTo("www.sub-merchant.com");
    assertThat(verifiedJwt.getStringClaim("merchantId")).isEqualTo("platformMerchantId");
  }

  @Test
  public void fromBase64EncodedNistP256PublicKey_rejectInvalidPublicKey() throws Exception {
    String invalidBased64EncodedEcNistP256PublicKey =
        "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2X=";
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtKeyConverter.fromBase64EncodedNistP256PublicKey(
                invalidBased64EncodedEcNistP256PublicKey));
  }

  @Test
  public void fromBased64EncodedPkcs8EcNistP256PrivateKey_rejectsIfPrivateAndPublicKeyDontMatch()
      throws Exception {
    String based64EncodedEcNistP256PublicKey =
        "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y=";
    String based64EncodedPkcs8EcNistP256PrivateKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
            + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
            + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";
    // This test key is taken from PaymentMethodTokenRecipientTest.java
    String otherBased64EncodedPkcs8EcNistP256PrivateKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOUIzccyJ3rTx6SVm"
            + "XrWdtwUP0NU26nvc8KIYw2GmYZKhRANCAAR5AjmTNAE93hQEQE+PryLlgr6Q7FXyN"
            + "XoZRk+1Fikhq61mFhQ9s14MOwGBxd5O6Jwn/sdUrWxkYk3idtNEN1Rz";
    JwtEcdsaPublicKey jwtEcdsaPublicKey =
        JwtKeyConverter.fromBase64EncodedNistP256PublicKey(based64EncodedEcNistP256PublicKey);
    // Correct key pair works
    JwtEcdsaPrivateKey unused =
        JwtKeyConverter.fromBased64EncodedPkcs8EcNistP256PrivateKey(
            based64EncodedPkcs8EcNistP256PrivateKey,
            jwtEcdsaPublicKey,
            InsecureSecretKeyAccess.get());
    // Incorrect key pair fails.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtKeyConverter.fromBased64EncodedPkcs8EcNistP256PrivateKey(
                otherBased64EncodedPkcs8EcNistP256PrivateKey,
                jwtEcdsaPublicKey,
                InsecureSecretKeyAccess.get()));
  }

  @Test
  public void fromBased64EncodedPkcs8EcNistP256PrivateKey_rejectsUnsupportedKidStrategy()
      throws Exception {
    String based64EncodedEcNistP256PublicKey =
        "BOdoXP+9Aq473SnGwg3JU1aiNpsd9vH2ognq4PtDtlLGa3Kj8TPf+jaQNPyDSkh3JUhiS0KyrrlWhAgNZKHYF2Y=";
    String based64EncodedPkcs8EcNistP256PrivateKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjj"
            + "chHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx"
            + "9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm";
    // Create a valid JwtEcdsaPublicKey with an unsupported KidStrategy.
    ECPublicKey ecPublicKey =
        EllipticCurves.getEcPublicKey(
            EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Base64.decode(based64EncodedEcNistP256PublicKey));
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    JwtEcdsaPublicKey jwtEcdsaPublicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(ecPublicKey.getW())
            .setIdRequirement(42)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtKeyConverter.fromBased64EncodedPkcs8EcNistP256PrivateKey(
                based64EncodedPkcs8EcNistP256PrivateKey,
                jwtEcdsaPublicKey,
                InsecureSecretKeyAccess.get()));
  }

  @Test
  public void rejectsP521KeyPair() throws Exception {
    // Generated using openssl with ecparam name "secp521r1"
    String based64EncodedEcNistP521PublicKey =
        "BAGrUqSU/JV9e2Qv2UpztXzAtpjeSoOQmT8mhOGPLaOBPVQF7yjOSQ6xq5bHVaPVIsyHD/8Vi/hbuXXdsnIpd"
            + "4ktBwDw2ZOVt/slhAMiL8b8JDJiunElAcMaYez1sE6sA2nz8+zOXSSaE7t0QNrZeqSBh+72h3xRzPjE"
            + "X6NqxTXEb57/dw==";
    String based64EncodedPkcs8EcNistP521PrivateKey =
        "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAuiYlht+iJoOSd5MV8lId2nH7cR99C6Wi+zgoY"
            + "yNDXVA9UFHD6lvGnyQF54h09871Z2lTvcTfgrdEQEAZTdsODfuhgYkDgYYABAADMx5VUF9kXD8jeonE"
            + "kb9IIQcMlnrXVLNd9MnV5515MosWidViaYRiTQMHlgbpiYL5XB6F5WJrPKcWN71kGncYSAE1rOJnju7"
            + "vMZKb5aW0szj/1dmU278X9U18vWvsxzTC+rrT+Cs36uXkiR9ugdsC5/SFtn2VoW9uC9gbGSxC2tHKzg==";

    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtKeyConverter.fromBase64EncodedNistP256PublicKey(based64EncodedEcNistP521PublicKey));

    // Create a valid JwtEcdsaPublicKey with an unsupported Curve.
    ECPublicKey ecPublicKey =
        EllipticCurves.getEcPublicKey(
            EllipticCurves.CurveType.NIST_P521,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Base64.decode(based64EncodedEcNistP521PublicKey));
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
            .build();
    JwtEcdsaPublicKey jwtEcdsaPublicKey =
        JwtEcdsaPublicKey.builder()
            .setParameters(parameters)
            .setPublicPoint(ecPublicKey.getW())
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            JwtKeyConverter.fromBased64EncodedPkcs8EcNistP256PrivateKey(
                based64EncodedPkcs8EcNistP521PrivateKey,
                jwtEcdsaPublicKey,
                InsecureSecretKeyAccess.get()));
  }
}
