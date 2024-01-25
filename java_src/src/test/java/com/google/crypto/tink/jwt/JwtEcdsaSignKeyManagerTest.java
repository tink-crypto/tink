// Copyright 2020 Google LLC
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
package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.testing.TestUtil;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for JwtEcdsaSignKeyManager. */
@RunWith(Theories.class)
public class JwtEcdsaSignKeyManagerTest {

  @BeforeClass
  public static void setUp() throws Exception {
    JwtSignatureConfig.register();
    SignatureConfig.register();
  }

  @DataPoints("parametersAlgos")
  public static final JwtEcdsaParameters.Algorithm[] PARAMETERS_ALGOS =
      new JwtEcdsaParameters.Algorithm[] {
        JwtEcdsaParameters.Algorithm.ES256,
        JwtEcdsaParameters.Algorithm.ES384,
        JwtEcdsaParameters.Algorithm.ES512
      };

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "JWT_ES256", "JWT_ES384", "JWT_ES512", "JWT_ES256_RAW", "JWT_ES384_RAW", "JWT_ES512_RAW",
      };

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    int numKeys = 10;
    Parameters p = KeyTemplates.get("JWT_ES256").toParameters();
    Set<BigInteger> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      JwtEcdsaPrivateKey key = (JwtEcdsaPrivateKey) KeysetHandle.generateNew(p).getAt(0).getKey();
      keys.add(key.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void testJwtES256RawTemplate_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .build());
  }

  @Test
  public void testJwtES384RawTemplate_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES384_RAW");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .build());
  }

  @Test
  public void testJwtES512RawTemplate_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES512_RAW");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .build());
  }

  @Test
  public void testJwtES256Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .build());
  }

  @Test
  public void testJwtES384Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES384");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES384)
                .build());
  }

  @Test
  public void testJwtES512Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES512");
    assertThat(template.toParameters())
        .isEqualTo(
            JwtEcdsaParameters.builder()
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES512)
                .build());
  }

  @Theory
  public void testTemplates(@FromDataPoints("templates") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_success(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
    assertThat(verifiedToken.hasTypeHeader()).isFalse();

    RawJwt rawTokenWithType =
        RawJwt.newBuilder().setTypeHeader("typeHeader").withoutExpiration().build();
    String signedCompactWithType = signer.signAndEncode(rawTokenWithType);
    VerifiedJwt verifiedTokenWithType =
        verifier.verifyAndDecode(
            signedCompactWithType,
            JwtValidator.newBuilder()
                .allowMissingExpiration()
                .expectTypeHeader("typeHeader")
                .build());
    assertThat(verifiedTokenWithType.getTypeHeader()).isEqualTo("typeHeader");
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerifyDifferentKey_throw(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    KeysetHandle otherHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeyVerify otherVerifier =
        otherHandle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> otherVerifier.verifyAndDecode(signedCompact, validator));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_header_modification_throw(
      @FromDataPoints("templates") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("issuer").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the header by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String header = new String(Base64.urlSafeDecode(parts[0]), UTF_8);
    String headerBase64 = Base64.urlSafeEncode((header + " ").getBytes(UTF_8));
    String modifiedCompact = headerBase64 + "." + parts[1] + "." + parts[2];

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_payload_modification_throw(
      @FromDataPoints("templates") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);

    // Modify the payload by adding a space at the end.
    String[] parts = signedCompact.split("\\.", -1);
    String payload = new String(Base64.urlSafeDecode(parts[1]), UTF_8);
    String payloadBase64 = Base64.urlSafeEncode((payload + " ").getBytes(UTF_8));
    String modifiedCompact = parts[0] + "." + payloadBase64 + "." + parts[2];

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(modifiedCompact, validator));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createSignVerify_bitFlipped_throw(@FromDataPoints("templates") String templateName)
      throws Exception {
    if (TestUtil.isTsan()) {
      // KeysetHandle.generateNew is too slow in Tsan.
      // We do not use assume because Theories expects to find something which is not skipped.
      return;
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("id123").withoutExpiration().build();
    String result = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
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
            () -> verifier.verifyAndDecode(new String(invalidJwt), validator));
      }
    }
  }

  private static String generateSignedCompact(
      PublicKeySign rawSigner, JsonObject header, JsonObject payload)
      throws GeneralSecurityException {
    String payloadBase64 = Base64.urlSafeEncode(payload.toString().getBytes(UTF_8));
    String headerBase64 = Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
    String unsignedCompact = headerBase64 + "." + payloadBase64;
    String signature =
        Base64.urlSafeEncode(rawSigner.sign(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  @Test
  public void createSignVerifyRaw_withDifferentHeaders() throws Exception {
    assumeFalse(TestUtil.isTsan());  // KeysetHandle.generateNew is too slow in Tsan.
    KeysetHandle handle =
        KeysetHandle.generateNew(
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
                .build());

    com.google.crypto.tink.jwt.JwtEcdsaPrivateKey key =
        (com.google.crypto.tink.jwt.JwtEcdsaPrivateKey) handle.getAt(0).getKey();
    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(key.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(key.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(PublicKeySign.class);

    JsonObject payload = new JsonObject();
    payload.addProperty("jid", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    // Normal, valid signed compact.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty("alg", "ES256");
    String normalSignedCompact = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalSignedCompact, validator);

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", "ES256");
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(nonJwtSigner, goodHeader, payload);
    unused =
        verifier.verifyAndDecode(
            goodSignedCompact,
            JwtValidator.newBuilder()
                .expectTypeHeader("typeHeader")
                .allowMissingExpiration()
                .build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(nonJwtSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with a valid but incorrect algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS256");
    String badAlgoSignedCompact = generateSignedCompact(nonJwtSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // for raw keys, the validation should work even if a "kid" header is present.
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty("alg", "ES256");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    unused = verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Test
  public void createSignVerifyTink_withDifferentHeaders() throws Exception {
    assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    KeysetHandle handle =
        KeysetHandle.generateNew(
            JwtEcdsaParameters.builder()
                .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
                .setKidStrategy(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());

    com.google.crypto.tink.jwt.JwtEcdsaPrivateKey key =
        (com.google.crypto.tink.jwt.JwtEcdsaPrivateKey) handle.getAt(0).getKey();
    EcdsaParameters nonJwtParameters =
        EcdsaParameters.builder()
            // JWT uses IEEE_P1363
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    EcdsaPublicKey nonJwtPublicKey =
        EcdsaPublicKey.builder()
            .setParameters(nonJwtParameters)
            .setPublicPoint(key.getPublicKey().getPublicPoint())
            .build();
    EcdsaPrivateKey nonJwtPrivateKey =
        EcdsaPrivateKey.builder()
            .setPublicKey(nonJwtPublicKey)
            .setPrivateValue(key.getPrivateValue())
            .build();
    // This nonJwtSigner computes signatures in the same way as one obtained from handle -- except
    // that it doesn't do any of the JWT stuff.
    PublicKeySign nonJwtSigner =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(nonJwtPrivateKey).makePrimary().withRandomId())
            .build()
            .getPrimitive(PublicKeySign.class);

    String kid = key.getPublicKey().getKid().get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    // Normal, valid signed token.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty("alg", "ES256");
    normalHeader.addProperty("kid", kid);
    String normalToken = generateSignedCompact(nonJwtSigner, normalHeader, payload);
    Object unused = verifier.verifyAndDecode(normalToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty("alg", "ES256");
    String tokenWithoutKid = generateSignedCompact(nonJwtSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in the header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(nonJwtSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("kid", kid);
    headerWithBadAlg.addProperty("alg", "RS256");
    String badAlgToken = generateSignedCompact(nonJwtSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(badAlgToken, validator));

    // token with an unknown kid header
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty("alg", "ES256");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(nonJwtSigner, unknownKidHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(unknownKidSignedCompact, validator));
  }

  /* Create a new keyset handle with the "custom_kid" value set. */
  private KeysetHandle withCustomKid(KeysetHandle keysetHandle, String customKid)
      throws Exception {
    com.google.crypto.tink.jwt.JwtEcdsaPrivateKey originalPrivateKey =
        (com.google.crypto.tink.jwt.JwtEcdsaPrivateKey) keysetHandle.getAt(0).getKey();
    JwtEcdsaParameters customKidParameters =
        JwtEcdsaParameters.builder()
            .setAlgorithm(originalPrivateKey.getParameters().getAlgorithm())
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.CUSTOM)
            .build();
    com.google.crypto.tink.jwt.JwtEcdsaPublicKey customKidPublicKey =
        com.google.crypto.tink.jwt.JwtEcdsaPublicKey.builder()
            .setParameters(customKidParameters)
            .setPublicPoint(originalPrivateKey.getPublicKey().getPublicPoint())
            .setCustomKid(customKid)
            .build();
    com.google.crypto.tink.jwt.JwtEcdsaPrivateKey customKidPrivateKey =
        com.google.crypto.tink.jwt.JwtEcdsaPrivateKey.create(
            customKidPublicKey, originalPrivateKey.getPrivateValue());
    return KeysetHandle.newBuilder()
        .addEntry(KeysetHandle.importKey(customKidPrivateKey).makePrimary().withRandomId())
        .build();
  }

  @Test
  public void signAndVerifyWithCustomKid() throws Exception {
    assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handleWithoutKid = KeysetHandle.generateNew(template);
    KeysetHandle handleWithKid =
        withCustomKid(handleWithoutKid, "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

    JwtPublicKeySign signerWithKid = handleWithKid.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeySign signerWithoutKid = handleWithoutKid.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);
    String signedCompactWithoutKid = signerWithoutKid.signAndEncode(rawToken);

    // Verify the kid in the header
    String jsonHeaderWithKid = JwtFormat.splitSignedCompact(signedCompactWithKid).header;
    String kid = JsonUtil.parseJson(jsonHeaderWithKid).get("kid").getAsString();
    assertThat(kid).isEqualTo("Lorem ipsum dolor sit amet, consectetur adipiscing elit");
    String jsonHeaderWithoutKid = JwtFormat.splitSignedCompact(signedCompactWithoutKid).header;
    assertThat(JsonUtil.parseJson(jsonHeaderWithoutKid).has("kid")).isFalse();

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithoutKid =
        handleWithoutKid.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    JwtPublicKeyVerify verifierWithKid =
        handleWithKid.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    // Even if custom_kid is set, we don't require a "kid" in the header.
    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithKid, validator).getJwtId())
        .isEqualTo("jwtId");

    assertThat(verifierWithoutKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(verifierWithKid.verifyAndDecode(signedCompactWithoutKid, validator).getJwtId())
        .isEqualTo("jwtId");
  }

  @Test
  public void signAndVerifyWithWrongCustomKid_fails() throws Exception {
    assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.

    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handleWithoutKid = KeysetHandle.generateNew(template);
    KeysetHandle handleWithKid = withCustomKid(handleWithoutKid, "kid");
    KeysetHandle handleWithWrongKid = withCustomKid(handleWithoutKid, "wrong kid");

    JwtPublicKeySign signerWithKid = handleWithKid.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String signedCompactWithKid = signerWithKid.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifierWithWrongKid =
        handleWithWrongKid.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    assertThrows(
        JwtInvalidException.class,
        () -> verifierWithWrongKid.verifyAndDecode(signedCompactWithKid, validator));
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Test
  public void testKeyManagersRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getUntypedKeyManager("type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"))
        .isNotNull();
  }
}
