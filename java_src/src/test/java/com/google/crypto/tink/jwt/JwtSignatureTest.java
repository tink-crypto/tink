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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.daead.DeterministicAeadConfig;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import org.junit.BeforeClass;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests the JWT signature primitives. Uses only the public API. */
@RunWith(Theories.class)
public final class JwtSignatureTest {

  @BeforeClass
  public static void setUp() throws Exception {
    JwtSignatureConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromIncompatbileKeyset_throws.
  }

  @DataPoints("jwt_signature_templates")
  public static final String[] TEMPLATES =
      new String[] {
        "JWT_ES256", "JWT_ES512_RAW", "JWT_RS256_2048_F4", "JWT_PS256_3072_F4_RAW",
      };

  @Theory
  public void createSignVerifyJwt(@FromDataPoints("jwt_signature_templates") String templateName)
      throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeySign jwtPublicKeySign = handle.getPrimitive(JwtPublicKeySign.class);
    Instant now = Clock.systemUTC().instant();
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setIssuer("issuer")
            .addAudience("audience")
            .setSubject("subject")
            .addStringClaim("claimName", "claimValue")
            .setExpiration(now.plusSeconds(100))
            .build();
    String token = jwtPublicKeySign.signAndEncode(rawJwt);

    JwtPublicKeyVerify jwtPublicKeyVerify =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("issuer").expectAudience("audience").build();
    VerifiedJwt verifiedJwt = jwtPublicKeyVerify.verifyAndDecode(token, validator);
    assertThat(verifiedJwt.getSubject()).isEqualTo("subject");
    assertThat(verifiedJwt.getStringClaim("claimName")).isEqualTo("claimValue");

    String expiredToken =
        jwtPublicKeySign.signAndEncode(
            RawJwt.newBuilder()
                .setIssuer("issuer")
                .addAudience("audience")
                .setExpiration(now.minusSeconds(100))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () -> jwtPublicKeyVerify.verifyAndDecode(expiredToken, validator));

    String tokenWithInvalidIssuer =
        jwtPublicKeySign.signAndEncode(
            RawJwt.newBuilder()
                .setIssuer("invalid")
                .addAudience("audience")
                .setSubject("subject")
                .addStringClaim("claimName", "claimValue")
                .setExpiration(now.minusSeconds(100))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () -> jwtPublicKeyVerify.verifyAndDecode(tokenWithInvalidIssuer, validator));

    String tokenWithInvalidAudience =
        jwtPublicKeySign.signAndEncode(
            RawJwt.newBuilder()
                .setIssuer("issuer")
                .addAudience("invalid")
                .setSubject("subject")
                .addStringClaim("claimName", "claimValue")
                .setExpiration(now.minusSeconds(100))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () -> jwtPublicKeyVerify.verifyAndDecode(tokenWithInvalidAudience, validator));

    KeysetHandle otherHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtPublicKeyVerify otherJwtPublicKeyVerify =
        otherHandle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    assertThrows(
        GeneralSecurityException.class,
        () -> otherJwtPublicKeyVerify.verifyAndDecode(token, validator));

    assertThrows(
        GeneralSecurityException.class,
        () -> jwtPublicKeyVerify.verifyAndDecode("invalid", validator));
    assertThrows(
        GeneralSecurityException.class, () -> jwtPublicKeyVerify.verifyAndDecode("", validator));
  }

  // A keyset with one JWT public key sign keyset, serialized in Tink's JSON format.
  private static final String JSON_JWT_PUBLIC_KEY_SIGN_KEYSET =
      "{  \"primaryKeyId\": 1742360595,  \"key\": [    {      \"keyData\": {        \"typeUrl\":"
          + " \"type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey\",        \"value\":"
          + " \"GiBgVYdAPg3Fa2FVFymGDYrI1trHMzVjhVNEMpIxG7t0HRJGIiBeoDMF9LS5BDCh6YgqE3DjHwWwnEKEI3WpPf8izEx1rRogbjQTXrTcw/1HKiiZm2Hqv41w7Vd44M9koyY/+VsP+SAQAQ==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PRIVATE\"      },      \"status\":"
          + " \"ENABLED\",      \"keyId\": 1742360595,      \"outputPrefixType\": \"TINK\"    }  ]"
          + "}";

  // A keyset with one JWT public key verify keyset, serialized in Tink's JSON format.
  private static final String JSON_JWT_PUBLIC_KEY_VERIFY_KEYSET =
      "{  \"primaryKeyId\": 1742360595,  \"key\": [    {      \"keyData\": {        \"typeUrl\":"
          + " \"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey\",        \"value\":"
          + " \"EAEaIG40E1603MP9RyoomZth6r+NcO1XeODPZKMmP/lbD/kgIiBeoDMF9LS5BDCh6YgqE3DjHwWwnEKEI3WpPf8izEx1rQ==\","
          + "        \"keyMaterialType\": \"ASYMMETRIC_PUBLIC\"      },      \"status\":"
          + " \"ENABLED\",      \"keyId\": 1742360595,      \"outputPrefixType\": \"TINK\"    }  ]"
          + "}";

  @Theory
  public void readKeysetSignVerifyJwt_success() throws Exception {
    KeysetHandle privateHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_JWT_PUBLIC_KEY_SIGN_KEYSET, InsecureSecretKeyAccess.get());
    Instant now = Clock.systemUTC().instant();
    JwtPublicKeySign jwtPublicKeySign = privateHandle.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setIssuer("issuer")
            .addAudience("audience")
            .setSubject("subject")
            .setExpiration(now.plusSeconds(100))
            .build();
    String token = jwtPublicKeySign.signAndEncode(rawJwt);

    KeysetHandle publicHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            JSON_JWT_PUBLIC_KEY_VERIFY_KEYSET, InsecureSecretKeyAccess.get());
    JwtPublicKeyVerify jwtPublicKeyVerify = publicHandle.getPrimitive(JwtPublicKeyVerify.class);
    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("issuer").expectAudience("audience").build();
    VerifiedJwt verifiedJwt = jwtPublicKeyVerify.verifyAndDecode(token, validator);
    assertThat(verifiedJwt.getSubject()).isEqualTo("subject");
  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the
  // JwtPublicKeySign or JwtPublicKeyVerify primitive.
  private static final String JSON_DAEAD_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 961932622,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesSivKey\","
          + "        \"keyMaterialType\": \"SYMMETRIC\","
          + "        \"value\": \"EkCJ9r5iwc5uxq5ugFyrHXh5dijTa7qalWUgZ8Gf08RxNd545FjtLMYL7ObcaFtCS"
          + "kvV2+7u6F2DN+kqUjAfkf2W\""
          + "      },"
          + "      \"outputPrefixType\": \"TINK\","
          + "      \"keyId\": 961932622,"
          + "      \"status\": \"ENABLED\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void getPrimitiveFromIncompatbileKeyset_throws() throws Exception {
    KeysetHandle handle =
        TinkJsonProtoKeysetFormat.parseKeyset(JSON_DAEAD_KEYSET, InsecureSecretKeyAccess.get());
    Object unused = handle.getPrimitive(DeterministicAead.class);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(JwtPublicKeySign.class));
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(JwtPublicKeyVerify.class));
  }
}
