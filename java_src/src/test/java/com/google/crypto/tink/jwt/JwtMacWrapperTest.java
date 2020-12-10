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
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JwtMacWrapper. */
@RunWith(JUnit4.class)
public class JwtMacWrapperTest {
  private final JwtMacWrapper wrapper = new JwtMacWrapper();

  @Before
  public void setUp() throws GeneralSecurityException {
    JwtMacConfig.register();
  }

  @Test
  public void test_wrapEmpty_throws() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);

    try {
      wrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void test_wrapNoPrimary_throws() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    primitiveSet.addPrimitive(
        new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    try {
      wrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void test_wrapNoRaw_throws() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    primitiveSet.addPrimitive(
        new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build());
    PrimitiveSet.Entry<JwtMac> entry =
        primitiveSet.addPrimitive(
            new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
            Keyset.Key.newBuilder()
                .setKeyId(202021)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    primitiveSet.setPrimary(entry);

    try {
      wrapper.wrap(primitiveSet);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void test_wrapSingle_works() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    PrimitiveSet.Entry<JwtMac> entry =
        primitiveSet.addPrimitive(
            new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC")),
            Keyset.Key.newBuilder()
                .setKeyId(202020)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    primitiveSet.setPrimary(entry);
    JwtMac wrapped = wrapper.wrap(primitiveSet);

    ToBeSignedJwt tbs = new ToBeSignedJwt.Builder().setJwtId("blah").build();
    String compact = wrapped.createCompact(tbs);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrapped.verifyCompact(compact, validator);

    assertThat(token.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void test_wrapMultiple_works() throws Exception {
    PrimitiveSet<JwtMac> primitiveSet = PrimitiveSet.newPrimitiveSet(JwtMac.class);
    JwtMac mac1 = new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC"));
    primitiveSet.addPrimitive(
        mac1,
        Keyset.Key.newBuilder()
            .setKeyId(202020)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build());

    JwtMac mac2 = new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(32), "HMAC"));
    PrimitiveSet.Entry<JwtMac> entry =
        primitiveSet.addPrimitive(
            mac2,
            Keyset.Key.newBuilder()
                .setKeyId(202021)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());

    primitiveSet.setPrimary(entry);
    JwtMac wrapped = wrapper.wrap(primitiveSet);

    ToBeSignedJwt tbs = new ToBeSignedJwt.Builder().setJwtId("blah").build();
    String compact = wrapped.createCompact(tbs);
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = wrapped.verifyCompact(compact, validator);
    VerifiedJwt token2 = mac2.verifyCompact(compact, validator);

    assertThrows(GeneralSecurityException.class, () -> mac1.verifyCompact(compact, validator));
    assertThat(token.getJwtId()).isEqualTo("blah");
    assertThat(token2.getJwtId()).isEqualTo("blah");
  }

  @Test
  public void wrongKey_throwsInvalidSignatureException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    ToBeSignedJwt toBeSignedJwt = new ToBeSignedJwt.Builder().build();
    String compact = jwtMac.createCompact(toBeSignedJwt);
    JwtValidator validator = new JwtValidator.Builder().build();

    KeysetHandle wrongKeysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac wrongJwtMac = wrongKeysetHandle.getPrimitive(JwtMac.class);
    assertThrows(
        GeneralSecurityException.class, () -> wrongJwtMac.verifyCompact(compact, validator));
  }

  @Test
  public void wrongIssuer_throwsInvalidException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    ToBeSignedJwt toBeSignedJwt = new ToBeSignedJwt.Builder().setIssuer("Justus").build();
    String compact = jwtMac.createCompact(toBeSignedJwt);
    JwtValidator validator = new JwtValidator.Builder().setIssuer("Peter").build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyCompact(compact, validator));
  }

  @Test
  public void expiredCompact_throwsExpiredException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);
    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    ToBeSignedJwt toBeSignedJwt =
        new ToBeSignedJwt.Builder()
            .setExpiration(now.minusSeconds(100)) // exipired 100 seconds ago
            .setIssuedAt(now.minusSeconds(200))
            .build();
    String compact = jwtMac.createCompact(toBeSignedJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyCompact(compact, validator));
  }

  @Test
  public void notYetValidCompact_throwsNotBeforeException() throws Exception {
    KeysetHandle keysetHandle = KeysetHandle.generateNew(JwtHmacKeyManager.hs256Template());
    JwtMac jwtMac = keysetHandle.getPrimitive(JwtMac.class);

    Instant now = Clock.systemUTC().instant().truncatedTo(ChronoUnit.SECONDS);
    ToBeSignedJwt toBeSignedJwt =
        new ToBeSignedJwt.Builder()
            .setNotBefore(now.plusSeconds(3600)) // is valid in 1 hour, but not before
            .setIssuedAt(now)
            .build();
    String compact = jwtMac.createCompact(toBeSignedJwt);
    JwtValidator validator = new JwtValidator.Builder().build();
    assertThrows(JwtInvalidException.class, () -> jwtMac.verifyCompact(compact, validator));
  }
}
