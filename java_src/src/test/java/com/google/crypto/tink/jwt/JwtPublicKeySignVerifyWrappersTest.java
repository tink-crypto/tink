// Copyright 2021 Google LLC
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

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Tests for JwtSignKeyverifyWrapper. */
@RunWith(JUnitParamsRunner.class)
public class JwtPublicKeySignVerifyWrappersTest {

  private static Object[] templateNamess() throws GeneralSecurityException {
    return new Object[] {
      "JWT_ES256",
      "JWT_ES384",
      "JWT_ES512",
      "JWT_ES256_RAW",
      "JWT_RS256_2048_F4",
      "JWT_RS256_3072_F4",
      "JWT_RS384_3072_F4",
      "JWT_RS512_4096_F4",
      "JWT_RS256_2048_F4_RAW",
      "JWT_PS256_2048_F4",
      "JWT_PS256_3072_F4",
      "JWT_PS384_3072_F4",
      "JWT_PS512_4096_F4",
      "JWT_PS256_2048_F4_RAW",
    };
  }

  @Before
  public void setUp() throws GeneralSecurityException {
    JwtSignatureConfig.register();
  }

  @Test
  public void test_noPrimary_getSignPrimitive_fails() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetManager manager = KeysetManager.withEmptyKeyset().add(template);
    KeysetHandle handle = manager.getKeysetHandle();
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(JwtPublicKeySign.class));
  }

  @Test
  public void test_noPrimary_getVerifyPrimitive_success() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetManager manager = KeysetManager.withEmptyKeyset().add(template);
    KeysetHandle publicHandle = manager.getKeysetHandle().getPublicKeysetHandle();
    publicHandle.getPrimitive(JwtPublicKeyVerify.class);
  }

  @Test
  public void test_wrapLegacy_throws() throws Exception {
    KeyTemplate rawTemplate = KeyTemplates.get("JWT_ES256_RAW");
    // Convert the normal, raw template into a template with output prefix type LEGACY
    KeyTemplate tinkTemplate =
        KeyTemplate.create(
            rawTemplate.getTypeUrl(), rawTemplate.getValue(), KeyTemplate.OutputPrefixType.LEGACY);
    KeysetHandle handle = KeysetHandle.generateNew(tinkTemplate);
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(JwtPublicKeySign.class));

    KeysetHandle publicHandle = handle.getPublicKeysetHandle();
    assertThrows(
        GeneralSecurityException.class, () -> publicHandle.getPrimitive(JwtPublicKeyVerify.class));
  }

  @Test
  public void test_wrapSingleTinkKey_works() throws Exception {
    KeyTemplate tinkTemplate = KeyTemplates.get("JWT_ES256");

    KeysetHandle handle = KeysetHandle.generateNew(tinkTemplate);

    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("blah").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void test_wrapSingleRawKey_works() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");
    KeysetHandle handle = KeysetHandle.generateNew(template);

    JwtPublicKeySign signer = handle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeyVerify verifier =
        handle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("blah").withoutExpiration().build();
    String signedCompact = signer.signAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    VerifiedJwt verifiedToken = verifier.verifyAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void test_wrapMultipleRawKeys() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256_RAW");

    KeysetManager manager = KeysetManager.withEmptyKeyset();
    manager.addNewKey(KeyTemplateProtoConverter.toProto(template), /*asPrimary=*/ true);
    KeysetHandle oldHandle = manager.getKeysetHandle();

    manager.addNewKey(KeyTemplateProtoConverter.toProto(template), /*asPrimary=*/ true);

    KeysetHandle newHandle = manager.getKeysetHandle();

    JwtPublicKeySign oldSigner = oldHandle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeySign newSigner = newHandle.getPrimitive(JwtPublicKeySign.class);

    JwtPublicKeyVerify oldVerifier =
        oldHandle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    JwtPublicKeyVerify newVerifier =
        newHandle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String oldSignedCompact = oldSigner.signAndEncode(rawToken);
    String newSignedCompact = newSigner.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThat(oldVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(newSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThrows(
        GeneralSecurityException.class,
        () -> oldVerifier.verifyAndDecode(newSignedCompact, validator));
  }

  @Test
  public void test_wrapMultipleTinkKeys() throws Exception {
    KeyTemplate tinkTemplate = KeyTemplates.get("JWT_ES256");

    KeysetManager manager = KeysetManager.withEmptyKeyset();
    manager.addNewKey(KeyTemplateProtoConverter.toProto(tinkTemplate), /*asPrimary=*/ true);
    KeysetHandle oldHandle = manager.getKeysetHandle();

    manager.addNewKey(KeyTemplateProtoConverter.toProto(tinkTemplate), /*asPrimary=*/ true);

    KeysetHandle newHandle = manager.getKeysetHandle();

    JwtPublicKeySign oldSigner = oldHandle.getPrimitive(JwtPublicKeySign.class);
    JwtPublicKeySign newSigner = newHandle.getPrimitive(JwtPublicKeySign.class);

    JwtPublicKeyVerify oldVerifier =
        oldHandle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
    JwtPublicKeyVerify newVerifier =
        newHandle.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);

    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").withoutExpiration().build();
    String oldSignedCompact = oldSigner.signAndEncode(rawToken);
    String newSignedCompact = newSigner.signAndEncode(rawToken);

    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThat(oldVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThat(newVerifier.verifyAndDecode(newSignedCompact, validator).getJwtId())
        .isEqualTo("jwtId");
    assertThrows(
        GeneralSecurityException.class,
        () -> oldVerifier.verifyAndDecode(newSignedCompact, validator));
  }

  @Test
  @Parameters(method = "templateNamess")
  public void wrongKey_throwsInvalidSignatureException(String templateName) throws Exception {
    KeyTemplate template = KeyTemplates.get(templateName);
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSign = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    RawJwt rawJwt = RawJwt.newBuilder().withoutExpiration().build();
    String compact = jwtSign.signAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();

    KeysetHandle wrongKeysetHandle = KeysetHandle.generateNew(template);
    KeysetHandle wrongPublicKeysetHandle = wrongKeysetHandle.getPublicKeysetHandle();

    JwtPublicKeyVerify wrongJwtVerify =
        wrongPublicKeysetHandle.getPrimitive(JwtPublicKeyVerify.class);
    assertThrows(
        GeneralSecurityException.class, () -> wrongJwtVerify.verifyAndDecode(compact, validator));
  }

  @Test
  public void wrongIssuer_throwsInvalidException() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier = publicHandle.getPrimitive(JwtPublicKeyVerify.class);
    RawJwt rawJwt = RawJwt.newBuilder().setIssuer("Justus").withoutExpiration().build();
    String compact = jwtSigner.signAndEncode(rawJwt);
    JwtValidator validator =
        JwtValidator.newBuilder().expectIssuer("Peter").allowMissingExpiration().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verifyAndDecode(compact, validator));
  }

  @Test
  public void expiredCompact_throwsInvalidException() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier = publicHandle.getPrimitive(JwtPublicKeyVerify.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setExpiration(now.minusSeconds(100)) // exipired 100 seconds ago
            .setIssuedAt(now.minusSeconds(200))
            .build();
    String compact = jwtSigner.signAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verifyAndDecode(compact, validator));
  }

  @Test
  public void notYetValidCompact_throwsInvalidException() throws Exception {
    KeyTemplate template = KeyTemplates.get("JWT_ES256");
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    JwtPublicKeySign jwtSigner = keysetHandle.getPrimitive(JwtPublicKeySign.class);
    KeysetHandle publicHandle = keysetHandle.getPublicKeysetHandle();
    JwtPublicKeyVerify jwtVerifier = publicHandle.getPrimitive(JwtPublicKeyVerify.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        RawJwt.newBuilder()
            .setNotBefore(now.plusSeconds(3600)) // is valid in 1 hour, but not before
            .setIssuedAt(now)
            .withoutExpiration()
            .build();
    String compact = jwtSigner.signAndEncode(rawJwt);
    JwtValidator validator = JwtValidator.newBuilder().allowMissingExpiration().build();
    assertThrows(JwtInvalidException.class, () -> jwtVerifier.verifyAndDecode(compact, validator));
  }
}
