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
import static org.junit.Assume.assumeFalse;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.proto.JwtEcdsaKeyFormat;
import com.google.crypto.tink.proto.JwtEcdsaPrivateKey;
import com.google.crypto.tink.proto.JwtEcdsaPublicKey;
import com.google.crypto.tink.proto.JwtEcdsaPublicKey.CustomKid;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
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
  }

  private final JwtEcdsaSignKeyManager manager = new JwtEcdsaSignKeyManager();
  private final KeyTypeManager.KeyFactory<JwtEcdsaKeyFormat, JwtEcdsaPrivateKey> factory =
      manager.keyFactory();

  private static JwtEcdsaKeyFormat createKeyFormat(JwtEcdsaAlgorithm algorithm) {
    return JwtEcdsaKeyFormat.newBuilder().setAlgorithm(algorithm).build();
  }

  @DataPoints("parametersAlgos")
  public static final JwtEcdsaAlgorithm[] PARAMETERS_ALGOS =
      new JwtEcdsaAlgorithm[] {
        JwtEcdsaAlgorithm.ES256, JwtEcdsaAlgorithm.ES384, JwtEcdsaAlgorithm.ES512
      };

  @DataPoints("templates")
  public static final String[] TEMPLATES =
      new String[] {
        "JWT_ES256", "JWT_ES384", "JWT_ES512", "JWT_ES256_RAW",
      };

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty_throw() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(JwtEcdsaKeyFormat.getDefaultInstance()));
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void validateKeyFormat_ok(@FromDataPoints("parametersAlgos") JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    JwtEcdsaKeyFormat format = createKeyFormat(algorithm);
    factory.validateKeyFormat(format);
  }

  private static void checkConsistency(JwtEcdsaPrivateKey privateKey, JwtEcdsaKeyFormat keyFormat) {
    assertThat(privateKey.getPublicKey().getAlgorithm()).isEqualTo(keyFormat.getAlgorithm());
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createKeys_ok(@FromDataPoints("parametersAlgos") JwtEcdsaAlgorithm algorithm)
      throws Exception {

    JwtEcdsaKeyFormat format = createKeyFormat(algorithm);
    JwtEcdsaPrivateKey key = factory.createKey(format);
    checkConsistency(key, format);
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createKey_alwaysNewElement_ok(
      @FromDataPoints("parametersAlgos") JwtEcdsaAlgorithm algorithm) throws Exception {

    JwtEcdsaKeyFormat format = createKeyFormat(algorithm);
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys -- takes about a
    // second per key.
    int numTests = 5;
    for (int i = 0; i < numTests; i++) {
      JwtEcdsaPrivateKey key = factory.createKey(format);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void getPublicKey_checkValues(
      @FromDataPoints("parametersAlgos") JwtEcdsaAlgorithm algorithm) throws Exception {
    JwtEcdsaPrivateKey privateKey = factory.createKey(createKeyFormat(algorithm));
    JwtEcdsaPublicKey publicKey = manager.getPublicKey(privateKey);

    assertThat(publicKey).isEqualTo(privateKey.getPublicKey());
  }

  // Note: we use Theory as a parametrized test -- different from what the Theory framework intends.
  @Theory
  public void createCorruptedPublicKeyPrimitive_throws(
      @FromDataPoints("parametersAlgos") JwtEcdsaAlgorithm algorithm) throws Exception {

    JwtEcdsaKeyFormat format = createKeyFormat(algorithm);
    JwtEcdsaPrivateKey originalKey = factory.createKey(format);
    byte[] originalPubX = originalKey.getPublicKey().getX().toByteArray();
    byte[] originalPubY = originalKey.getPublicKey().getY().toByteArray();
    originalPubX[0] = (byte) (originalPubX[0] ^ 0x01);
    ByteString corruptedPubX = ByteString.copyFrom(originalPubX);
    JwtEcdsaPublicKey corruptedPub =
        JwtEcdsaPublicKey.newBuilder()
            .setVersion(originalKey.getPublicKey().getVersion())
            .setAlgorithm(algorithm)
            .setX(corruptedPubX)
            .setY(ByteString.copyFrom(originalPubY))
            .build();
    JwtEcdsaPrivateKey corruptedKey =
        JwtEcdsaPrivateKey.newBuilder()
            .setVersion(originalKey.getVersion())
            .setPublicKey(corruptedPub)
            .setKeyValue(originalKey.getKeyValue())
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.getPrimitive(corruptedKey, JwtPublicKeySignInternal.class));
  }

  @Test
  public void testDeriveKey_throw() throws Exception {
    assertThrows(
        UnsupportedOperationException.class,
        () ->
            factory.deriveKey(
                JwtEcdsaKeyFormat.getDefaultInstance(),
                new ByteArrayInputStream(Random.randBytes(100))));
  }

  private static void checkTemplate(KeyTemplate template, JwtEcdsaAlgorithm algorithm)
      throws Exception {
    assertThat(template.getTypeUrl()).isEqualTo(new JwtEcdsaSignKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtEcdsaKeyFormat format =
        JwtEcdsaKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(format.getAlgorithm()).isEqualTo(algorithm);
  }

  @Test
  public void testJwtES256Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    checkTemplate(template, JwtEcdsaAlgorithm.ES256);
  }

  @Test
  public void testJwtES384Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES384_RAW");
    checkTemplate(template, JwtEcdsaAlgorithm.ES384);
  }

  @Test
  public void testJwtES512Template_ok() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES512_RAW");
    checkTemplate(template, JwtEcdsaAlgorithm.ES512);
  }

  @Test
  public void testKeyFormatsAreValid() throws Exception {
    for (KeyTypeManager.KeyFactory.KeyFormat<JwtEcdsaKeyFormat> format :
        factory.keyFormats().values()) {
      factory.validateKeyFormat(format.keyFormat);
    }
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
      EcdsaSignJce rawSigner, JsonObject header, JsonObject payload)
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
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);
    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);
    JwtEcdsaPrivateKey keyProto =
        JwtEcdsaPrivateKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            JwtEcdsaVerifyKeyManager.getCurve(keyProto.getPublicKey().getAlgorithm()),
            keyProto.getKeyValue().toByteArray());
    JwtEcdsaAlgorithm algorithm = keyProto.getPublicKey().getAlgorithm();
    Enums.HashType hash = JwtEcdsaVerifyKeyManager.hashForEcdsaAlgorithm(algorithm);
    EcdsaSignJce rawSigner = new EcdsaSignJce(privateKey, hash, EcdsaEncoding.IEEE_P1363);

    JsonObject payload = new JsonObject();
    payload.addProperty("jid", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    // Normal, valid signed compact.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty("alg", "ES256");
    String normalSignedCompact = generateSignedCompact(rawSigner, normalHeader, payload);
    verifier.verifyAndDecode(normalSignedCompact, validator);

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty("alg", "ES256");
    goodHeader.addProperty("typ", "typeHeader");
    String goodSignedCompact = generateSignedCompact(rawSigner, goodHeader, payload);
    verifier.verifyAndDecode(
        goodSignedCompact,
        JwtValidator.newBuilder().expectTypeHeader("typeHeader").allowMissingExpiration().build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(rawSigner, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with a valid but incorrect algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty("alg", "RS256");
    String badAlgoSignedCompact = generateSignedCompact(rawSigner, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(badAlgoSignedCompact, validator));

    // for raw keys, the validation should work even if a "kid" header is present.
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty("alg", "ES256");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(rawSigner, unknownKidHeader, payload);
    verifier.verifyAndDecode(unknownKidSignedCompact, validator);
  }

  @Test
  public void createSignVerifyTink_withDifferentHeaders() throws Exception {
    assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle handle = KeysetHandle.generateNew(template);
    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);
    JwtEcdsaPrivateKey keyProto =
        JwtEcdsaPrivateKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            JwtEcdsaVerifyKeyManager.getCurve(keyProto.getPublicKey().getAlgorithm()),
            keyProto.getKeyValue().toByteArray());
    JwtEcdsaAlgorithm algorithm = keyProto.getPublicKey().getAlgorithm();
    Enums.HashType hash = JwtEcdsaVerifyKeyManager.hashForEcdsaAlgorithm(algorithm);
    EcdsaSignJce rawSigner = new EcdsaSignJce(privateKey, hash, EcdsaEncoding.IEEE_P1363);
    String kid =
        JwtFormat.getKid(keyset.getKey(0).getKeyId(), keyset.getKey(0).getOutputPrefixType()).get();

    JsonObject payload = new JsonObject();
    payload.addProperty("jti", "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    // Normal, valid signed token.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty("alg", "ES256");
    normalHeader.addProperty("kid", kid);
    String normalToken = generateSignedCompact(rawSigner, normalHeader, payload);
    verifier.verifyAndDecode(normalToken, validator);

    // token without kid are rejected, even if they are valid.
    JsonObject headerWithoutKid = new JsonObject();
    headerWithoutKid.addProperty("alg", "ES256");
    String tokenWithoutKid = generateSignedCompact(rawSigner, headerWithoutKid, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutKid, validator));

    // token without algorithm in the header
    JsonObject headerWithoutAlg = new JsonObject();
    headerWithoutAlg.addProperty("kid", kid);
    String tokenWithoutAlg = generateSignedCompact(rawSigner, headerWithoutAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(tokenWithoutAlg, validator));

    // token with an incorrect algorithm in the header
    JsonObject headerWithBadAlg = new JsonObject();
    headerWithBadAlg.addProperty("kid", kid);
    headerWithBadAlg.addProperty("alg", "RS256");
    String badAlgToken = generateSignedCompact(rawSigner, headerWithBadAlg, payload);
    assertThrows(
        GeneralSecurityException.class, () -> verifier.verifyAndDecode(badAlgToken, validator));

    // token with an unknown kid header
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty("alg", "ES256");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(rawSigner, unknownKidHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verifyAndDecode(unknownKidSignedCompact, validator));
  }

  /* Create a new keyset handle with the "custom_kid" value set. */
  private KeysetHandle withCustomKid(KeysetHandle keysetHandle, String customKid)
      throws Exception {
    Keyset keyset = CleartextKeysetHandle.getKeyset(keysetHandle);
    JwtEcdsaPrivateKey privateKey =
        JwtEcdsaPrivateKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    JwtEcdsaPublicKey publicKeyWithKid =
        privateKey.getPublicKey().toBuilder()
            .setCustomKid(CustomKid.newBuilder().setValue(customKid).build())
            .build();
    JwtEcdsaPrivateKey privateKeyWithKid =
        privateKey.toBuilder().setPublicKey(publicKeyWithKid).build();
    KeyData keyDataWithKid =
        keyset.getKey(0).getKeyData().toBuilder()
            .setValue(privateKeyWithKid.toByteString())
            .build();
    Keyset.Key keyWithKid = keyset.getKey(0).toBuilder().setKeyData(keyDataWithKid).build();
    return CleartextKeysetHandle.fromKeyset(keyset.toBuilder().setKey(0, keyWithKid).build());
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
  public void signWithTinkKeyAndCustomKid_fails() throws Exception {
    assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle handleWithoutKid = KeysetHandle.generateNew(template);
    KeysetHandle handleWithKid =
        withCustomKid(handleWithoutKid, "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

    JwtPublicKeySign signerWithKid = handleWithKid.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    assertThrows(JwtInvalidException.class, () -> signerWithKid.signAndEncode(rawToken));
  }
}
