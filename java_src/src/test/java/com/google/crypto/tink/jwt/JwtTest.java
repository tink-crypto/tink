// Copyright 2022 Google LLC
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

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
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

/** Unit tests for the jwt package. Uses only the public API. */
@RunWith(Theories.class)
public final class JwtTest {

  @BeforeClass
  public static void setUp() throws Exception {
    JwtMacConfig.register();
    DeterministicAeadConfig.register(); // Needed for getPrimitiveFromNonMacKeyset_throws.
  }

  @DataPoints("jwt_mac_templates")
  public static final String[] TEMPLATES =
      new String[] {
        "JWT_HS256",
        "JWT_HS256_RAW",
        "JWT_HS384",
        "JWT_HS384_RAW",
        "JWT_HS512",
        "JWT_HS512_RAW",
      };

  @Theory
  public void createComputeVerifyJwtMac(@FromDataPoints("jwt_mac_templates") String templateName)
      throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtMac jwtMac = handle.getPrimitive(JwtMac.class);
    Instant now = Clock.systemUTC().instant();
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setIssuer("issuer")
            .addAudience("audience")
            .setSubject("subject")
            .addStringClaim("claimName", "claimValue")
            .setExpiration(now.plusSeconds(100))
            .build();
    String token = jwtMac.computeMacAndEncode(rawJwt);

    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("issuer").expectAudience("audience").build();
    VerifiedJwt verifiedJwt = jwtMac.verifyMacAndDecode(token, validator);
    assertThat(verifiedJwt.getSubject()).isEqualTo("subject");
    assertThat(verifiedJwt.getStringClaim("claimName")).isEqualTo("claimValue");

    String expiredToken =
        jwtMac.computeMacAndEncode(
            RawJwt.newBuilder()
                .setIssuer("issuer")
                .addAudience("audience")
                .setExpiration(now.minusSeconds(100))
                .build());
    assertThrows(
        GeneralSecurityException.class, () -> jwtMac.verifyMacAndDecode(expiredToken, validator));

    String tokenWithInvalidIssuer =
        jwtMac.computeMacAndEncode(
            RawJwt.newBuilder()
                .setIssuer("invalid")
                .addAudience("audience")
                .setSubject("subject")
                .addStringClaim("claimName", "claimValue")
                .setExpiration(now.minusSeconds(100))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () -> jwtMac.verifyMacAndDecode(tokenWithInvalidIssuer, validator));

    String tokenWithInvalidAudience =
        jwtMac.computeMacAndEncode(
            RawJwt.newBuilder()
                .setIssuer("issuer")
                .addAudience("invalid")
                .setSubject("subject")
                .addStringClaim("claimName", "claimValue")
                .setExpiration(now.minusSeconds(100))
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () -> jwtMac.verifyMacAndDecode(tokenWithInvalidAudience, validator));

    KeysetHandle otherHandle = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    JwtMac otherJwtMac = otherHandle.getPrimitive(JwtMac.class);
    assertThrows(
        GeneralSecurityException.class, () -> otherJwtMac.verifyMacAndDecode(token, validator));

    assertThrows(
        GeneralSecurityException.class, () -> jwtMac.verifyMacAndDecode("invalid", validator));
    assertThrows(
        GeneralSecurityException.class, () -> jwtMac.verifyMacAndDecode("", validator));
  }

  // A keyset with one JWT MAC key, serialized in Tink's JSON format.
  private static final String JSON_JWT_MAC_KEYSET =
      ""
          + "{"
          + "  \"primaryKeyId\": 1685620571,"
          + "  \"key\": ["
          + "    {"
          + "      \"keyData\": {"
          + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.JwtHmacKey\","
          + "        \"value\": \"GiDmRwUiwKDsPHd+2mSHwlLfzvkgoV5meopVKp+GCbhHthAB\","
          + "        \"keyMaterialType\": \"SYMMETRIC\""
          + "      },"
          + "      \"status\": \"ENABLED\","
          + "      \"keyId\": 1685620571,"
          + "      \"outputPrefixType\": \"TINK\""
          + "    }"
          + "  ]"
          + "}";

  @Theory
  public void readKeysetComputeVerifyJwtMac_success() throws Exception {
    KeysetHandle handle =
        CleartextKeysetHandle.read(JsonKeysetReader.withString(JSON_JWT_MAC_KEYSET));
    Instant now = Clock.systemUTC().instant();
    JwtMac jwtMac = handle.getPrimitive(JwtMac.class);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setIssuer("issuer")
            .addAudience("audience")
            .setSubject("subject")
            .setExpiration(now.plusSeconds(100))
            .build();
    String token = jwtMac.computeMacAndEncode(rawJwt);

    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("issuer").expectAudience("audience").build();
    VerifiedJwt verifiedJwt = jwtMac.verifyMacAndDecode(token, validator);
    assertThat(verifiedJwt.getSubject()).isEqualTo("subject");
  }

  // A keyset with multiple keys. The first key is the same as in JSON_AEAD_KEYSET.
  private static final String JSON_JWT_MAC_KEYSET_WITH_MULTIPLE_KEYS =
      ""
      + "{"
      + "  \"primaryKeyId\": 648866621,"
      + "  \"key\": ["
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.JwtHmacKey\","
      + "        \"value\": \"GiDmRwUiwKDsPHd+2mSHwlLfzvkgoV5meopVKp+GCbhHthAB\","
      + "        \"keyMaterialType\": \"SYMMETRIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 1685620571,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    },"
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.JwtHmacKey\","
      + "        \"value\":"
      + "\"GjBP5UIYeH40mAliduNPdvnkGqJci3mRpxjSHZ6jkBQ7ppuOGwpyBqsLobFspZOR+y0QAg==\","
      + "        \"keyMaterialType\": \"SYMMETRIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 648866621,"
      + "      \"outputPrefixType\": \"RAW\""
      + "    },"
      + "    {"
      + "      \"keyData\": {"
      + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.JwtHmacKey\","
      + "        \"value\": \"GkAjSoAXaQXhp8oHfEBdPUxKLWIA1hYNc+905NFRt0tYbDcje8LlPdmfVi8"
      + "Xno7+U1xc0EPPxGFGfKPcIetKccgoEAM=\","
      + "        \"keyMaterialType\": \"SYMMETRIC\""
      + "      },"
      + "      \"status\": \"ENABLED\","
      + "      \"keyId\": 923678323,"
      + "      \"outputPrefixType\": \"TINK\""
      + "    }"
      + "  ]"
      + "}";

  @Theory
  public void multipleKeysReadKeysetComputeVerifyJwtMac_success()
      throws Exception {
    KeysetHandle handle =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withString(JSON_JWT_MAC_KEYSET_WITH_MULTIPLE_KEYS));
    Instant now = Clock.systemUTC().instant();
    JwtMac jwtMac = handle.getPrimitive(JwtMac.class);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setIssuer("issuer")
            .addAudience("audience")
            .setSubject("subject")
            .setExpiration(now.plusSeconds(100))
            .build();
    String token = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("issuer").expectAudience("audience").build();
    VerifiedJwt verifiedJwt = jwtMac.verifyMacAndDecode(token, validator);
    assertThat(verifiedJwt.getSubject()).isEqualTo("subject");

    // Also test that jwtMac can verify tokens computed with a non-primary key. We use
    // JSON_JWT_MAC_KEYSET to compute a tag with the first key.
    KeysetHandle handle1 =
        CleartextKeysetHandle.read(JsonKeysetReader.withString(JSON_JWT_MAC_KEYSET));
    JwtMac jwtMac1 = handle1.getPrimitive(JwtMac.class);
    String token1 = jwtMac1.computeMacAndEncode(rawJwt);
    assertThat(jwtMac.verifyMacAndDecode(token1, validator).getSubject()).isEqualTo("subject");
  }

  // A keyset with a valid DeterministicAead key. This keyset can't be used with the Mac primitive.
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
  public void getPrimitiveFromNonMacKeyset_throws() throws Exception {
    KeysetHandle handle =
        CleartextKeysetHandle.read(
            JsonKeysetReader.withString(JSON_DAEAD_KEYSET));
    // Test that the keyset can create a DeterministicAead primitive, but not a JwtMac.
    handle.getPrimitive(DeterministicAead.class);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(JwtMac.class));
  }

  // TODO(juerg): Add tests for Jwt signatures.
}
