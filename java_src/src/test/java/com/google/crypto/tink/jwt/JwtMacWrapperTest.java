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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetManager;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JwtMacWrapper. */
@RunWith(JUnit4.class)
public class JwtMacWrapperTest {

  @Before
  public void setUp() throws GeneralSecurityException {
    JwtMacConfig.register();
  }

  @Test
  public void test_wrapNoPrimary_throws() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetManager manager = KeysetManager.withEmptyKeyset().add(template);
    KeysetHandle handle = manager.getKeysetHandle();
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(JwtMac.class));
  }

  @Test
  public void test_wrapNoRaw_throws() throws Exception {
    KeyTemplate rawTemplate = JwtHmacKeyManager.hs256Template();
    // Convert the normal, raw template into a template with output prefix type TINK
    KeyTemplate tinkTemplate =
        KeyTemplate.create(
            rawTemplate.getTypeUrl(), rawTemplate.getValue(), KeyTemplate.OutputPrefixType.TINK);
    KeysetHandle handle = KeysetHandle.generateNew(tinkTemplate);
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(JwtMac.class));
  }

  @Test
  public void test_wrapSingleKey_works() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);

    JwtMac jwtMac = handle.getPrimitive(JwtMac.class);
    RawJwt rawToken = new RawJwt.Builder().setJwtId("blah").build();
    String signedCompact = jwtMac.computeMacAndEncode(rawToken);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt verifiedToken = jwtMac.verifyMacAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void test_wrapMultipleKeys() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();

    KeysetManager manager = KeysetManager.withEmptyKeyset();
    manager.addNewKey(KeyTemplateProtoConverter.toProto(template), /*asPrimary=*/ true);
    KeysetHandle oldHandle = manager.getKeysetHandle();

    manager.addNewKey(KeyTemplateProtoConverter.toProto(template), /*asPrimary=*/ true);

    KeysetHandle newHandle = manager.getKeysetHandle();

    JwtMac oldJwtMac = oldHandle.getPrimitive(JwtMac.class);
    JwtMac newJwtMac = newHandle.getPrimitive(JwtMac.class);

    RawJwt rawToken = new RawJwt.Builder().setJwtId("blah").build();
    String oldSignedCompact = oldJwtMac.computeMacAndEncode(rawToken);
    String newSignedCompact = newJwtMac.computeMacAndEncode(rawToken);

    JwtValidator validator = new JwtValidator.Builder().build();
    assertThat(oldJwtMac.verifyMacAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("blah");
    assertThat(newJwtMac.verifyMacAndDecode(oldSignedCompact, validator).getJwtId())
        .isEqualTo("blah");
    assertThat(newJwtMac.verifyMacAndDecode(newSignedCompact, validator).getJwtId())
        .isEqualTo("blah");
    assertThrows(
        GeneralSecurityException.class,
        () -> oldJwtMac.verifyMacAndDecode(newSignedCompact, validator));
  }

  @Test
  public void wrongKey_throwsInvalidSignatureException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    RawJwt rawJwt = new RawJwt.Builder().build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();

    KeysetHandle wrongKeysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac wrongJwtMac = wrongKeysetHandle.getPrimitive(JwtMac.class);
    assertThrows(
        GeneralSecurityException.class, () -> wrongJwtMac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void wrongIssuer_throwsInvalidException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    RawJwt rawJwt = new RawJwt.Builder().setIssuer("Justus").build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().setIssuer("Peter").build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void expiredCompact_throwsExpiredException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        new RawJwt.Builder()
            .setExpiration(now.minusSeconds(100)) // exipired 100 seconds ago
            .setIssuedAt(now.minusSeconds(200))
            .build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void notYetValidCompact_throwsNotBeforeException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    RawJwt rawJwt =
        new RawJwt.Builder()
            .setNotBefore(now.plusSeconds(3600)) // is valid in 1 hour, but not before
            .setIssuedAt(now)
            .build();
    String compact = jwtMac.computeMacAndEncode(rawJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyMacAndDecode(compact, validator));
  }
}
