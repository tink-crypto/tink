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
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.MILLIS;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.proto.JwtHmacAlgorithm;
import com.google.crypto.tink.proto.JwtHmacKey;
import com.google.crypto.tink.proto.JwtHmacKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.spec.SecretKeySpec;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Unit tests for {@link JwtHmacKeyManager}. */
@RunWith(JUnitParamsRunner.class)
public class JwtHmacKeyManagerTest {
  private final JwtHmacKeyManager manager = new JwtHmacKeyManager();
  private final KeyTypeManager.KeyFactory<JwtHmacKeyFormat, JwtHmacKey> factory =
      manager.keyFactory();

  @BeforeClass
  public static void setUp() throws Exception {
    JwtMacConfig.register();
  }

  private static Object[] templates() {
    return new Object[] {
      JwtHmacKeyManager.hs256Template(),
      JwtHmacKeyManager.hs384Template(),
      JwtHmacKeyManager.hs512Template(),
    };
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(JwtHmacKeyFormat.getDefaultInstance()));
  }

  private static JwtHmacKeyFormat makeJwtHmacKeyFormat(int keySize, JwtHmacAlgorithm algorithm) {
    return JwtHmacKeyFormat.newBuilder().setAlgorithm(algorithm).setKeySize(keySize).build();
  }

  @Test
  public void validateKeyFormat_sha256() throws Exception {
    factory.validateKeyFormat(makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS256));
  }

  @Test
  public void validateKeyFormat_sha512() throws Exception {
    factory.validateKeyFormat(makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS512));
  }

  @Test
  public void validateKeyFormat_keySizeTooSmall_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(makeJwtHmacKeyFormat(31, JwtHmacAlgorithm.HS256)));
  }

  @Test
  public void testKeyFormatsAreValid() throws Exception {
    for (KeyTypeManager.KeyFactory.KeyFormat<JwtHmacKeyFormat> format :
        factory.keyFormats().values()) {
      factory.validateKeyFormat(format.keyFormat);
    }
  }

  @Test
  public void createKey_valid() throws Exception {
    manager.validateKey(factory.createKey(makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS256)));
    manager.validateKey(factory.createKey(makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS256)));
    manager.validateKey(factory.createKey(makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS512)));
  }

  @Test
  public void createKey_checkValues() throws Exception {
    JwtHmacKeyFormat keyFormat = makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS256);
    JwtHmacKey key = factory.createKey(keyFormat);
    assertThat(key.getKeyValue()).hasSize(keyFormat.getKeySize());
    assertThat(key.getAlgorithm()).isEqualTo(keyFormat.getAlgorithm());
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    JwtHmacKeyFormat keyFormat = makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS256);
    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; ++i) {
      keys.add(TestUtil.hexEncode(factory.createKey(keyFormat).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    JwtHmacKey validKey = factory.createKey(makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS256));
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(JwtHmacKey.newBuilder(validKey).setVersion(1).build()));
  }

  @Test
  public void validateKey_notValid_throws() throws Exception {
    JwtHmacKey validKey = factory.createKey(makeJwtHmacKeyFormat(32, JwtHmacAlgorithm.HS256));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            manager.validateKey(
                JwtHmacKey.newBuilder(validKey)
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(31)))
                    .build()));
  }

  @Test
  public void testDeriveKey_shouldThrowUnsupportedException() throws Exception {
    assertThrows(
        UnsupportedOperationException.class,
        () ->
            factory.deriveKey(
                JwtHmacKeyFormat.getDefaultInstance(),
                new ByteArrayInputStream(Random.randBytes(100))));
  }

  @Test
  public void testHs256Template() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    assertThat(template.getTypeUrl()).isEqualTo(manager.getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtHmacKeyFormat format =
        JwtHmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getAlgorithm()).isEqualTo(JwtHmacAlgorithm.HS256);
  }

  @Test
  public void testHs384Template() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs384Template();
    assertThat(template.getTypeUrl()).isEqualTo(new JwtHmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtHmacKeyFormat format =
        JwtHmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(48);
    assertThat(format.getAlgorithm()).isEqualTo(JwtHmacAlgorithm.HS384);
  }

  @Test
  public void testHs512Template() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs512Template();
    assertThat(template.getTypeUrl()).isEqualTo(new JwtHmacKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
    JwtHmacKeyFormat format =
        JwtHmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(format.getKeySize()).isEqualTo(64);
    assertThat(format.getAlgorithm()).isEqualTo(JwtHmacAlgorithm.HS512);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    testKeyTemplateCompatible(manager, JwtHmacKeyManager.hs256Template());
    testKeyTemplateCompatible(manager, JwtHmacKeyManager.hs384Template());
    testKeyTemplateCompatible(manager, JwtHmacKeyManager.hs512Template());
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerify_success(KeyTemplate template) throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac primitive = handle.getPrimitive(JwtMac.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").build();
    String signedCompact = primitive.computeMacAndEncode(rawToken);
    JwtValidator validator = JwtValidator.newBuilder().build();
    VerifiedJwt verifiedToken = primitive.verifyMacAndDecode(signedCompact, validator);
    assertThat(verifiedToken.getJwtId()).isEqualTo("jwtId");
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerifyDifferentKey_throw(KeyTemplate template) throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac primitive = handle.getPrimitive(JwtMac.class);
    RawJwt rawToken = RawJwt.newBuilder().setJwtId("jwtId").build();
    String compact = primitive.computeMacAndEncode(rawToken);

    KeysetHandle otherHandle = KeysetHandle.generateNew(template);
    JwtMac otherPrimitive = otherHandle.getPrimitive(JwtMac.class);
    JwtValidator validator = JwtValidator.newBuilder().build();
    assertThrows(
        GeneralSecurityException.class,
        () -> otherPrimitive.verifyMacAndDecode(compact, validator));
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerify_modifiedHeader_throw(KeyTemplate template) throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    String jwtId = "user123";
    RawJwt unverified = RawJwt.newBuilder().setJwtId(jwtId).build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().build();

    String[] parts = compact.split("\\.", -1);
    byte[] header = Base64.urlSafeDecode(parts[0]);

    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(header)) {
      String modifiedHeader = Base64.urlSafeEncode(mutation.value);
      String modifiedToken = modifiedHeader + "." + parts[1] + "." + parts[2];

      assertThrows(
          GeneralSecurityException.class, () -> mac.verifyMacAndDecode(modifiedToken, validator));
    }
  }

  @Test
  @Parameters(method = "templates")
  public void createSignVerify_modifiedPayload_throw(KeyTemplate template) throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    String jwtId = "user123";
    RawJwt unverified = RawJwt.newBuilder().setJwtId(jwtId).build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().build();

    String[] parts = compact.split("\\.", -1);
    byte[] payload = Base64.urlSafeDecode(parts[1]);

    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(payload)) {
      String modifiedPayload = Base64.urlSafeEncode(mutation.value);
      String modifiedToken = parts[0] + "." + modifiedPayload + "." + parts[2];

      assertThrows(
          GeneralSecurityException.class, () -> mac.verifyMacAndDecode(modifiedToken, validator));
    }
  }

  @Test
  @Parameters(method = "templates")
  public void verify_modifiedSignature_shouldThrow(KeyTemplate template) throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    String jwtId = "user123";
    RawJwt unverified = RawJwt.newBuilder().setJwtId(jwtId).build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().build();

    String[] parts = compact.split("\\.", -1);
    byte[] signature = Base64.urlSafeDecode(parts[1]);

    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(signature)) {
      String modifiedSignature = Base64.urlSafeEncode(mutation.value);
      String modifiedToken = parts[0] + "." + parts[1] + "." + modifiedSignature;

      assertThrows(
          GeneralSecurityException.class, () -> mac.verifyMacAndDecode(modifiedToken, validator));
    }
  }

  @Test
  public void computeVerify_canGetData() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    String issuer = "google";
    String audience = "mybank";
    String jwtId = "user123";
    double amount = 0.1;
    RawJwt unverified =
        RawJwt.newBuilder()
            .setTypeHeader("myType")
            .setIssuer(issuer)
            .addAudience(audience)
            .setJwtId(jwtId)
            .addNumberClaim("amount", amount)
            .build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator =
        JwtValidator.newBuilder()
            .expectTypeHeader("myType")
            .expectIssuer(issuer)
            .expectAudience(audience)
            .build();
    VerifiedJwt token = mac.verifyMacAndDecode(compact, validator);

    assertThat(token.getTypeHeader()).isEqualTo("myType");
    assertThat(token.getNumberClaim("amount")).isEqualTo(amount);
    assertThat(token.getIssuer()).isEqualTo(issuer);
    assertThat(token.getAudiences()).containsExactly(audience);
    assertThat(token.getJwtId()).isEqualTo(jwtId);
  }

  @Test
  public void verify_expired_shouldThrow() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    RawJwt token =
        RawJwt.newBuilder()
            .setExpiration(clock1.instant().plus(Duration.ofMinutes(1)))
            .build();
    String compact = mac.computeMacAndEncode(token);

    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = JwtValidator.newBuilder().setClock(clock2).build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void verify_notExpired_success() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    Clock clock = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    Instant expiration = clock.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        RawJwt.newBuilder().setExpiration(expiration).build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().build();
    VerifiedJwt token = mac.verifyMacAndDecode(compact, validator);

    assertThat(token.getExpiration()).isEqualTo(expiration.truncatedTo(MILLIS));
  }

  @Test
  public void verify_notExpired_clockSkew_success() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minutes in the future.
    Instant expiration = clock1.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        RawJwt.newBuilder().setExpiration(expiration).build();
    String compact = mac.computeMacAndEncode(unverified);

    // A clock skew of 1 minute is allowed.
    JwtValidator validator = JwtValidator.newBuilder().setClockSkew(Duration.ofMinutes(1)).build();
    VerifiedJwt token = mac.verifyMacAndDecode(compact, validator);

    assertThat(token.getExpiration()).isEqualTo(expiration.truncatedTo(MILLIS));
  }

  @Test
  public void verify_before_shouldThrow() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    Clock clock = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        RawJwt.newBuilder().setNotBefore(notBefore).build();
    String compact = mac.computeMacAndEncode(unverified);

    JwtValidator validator = JwtValidator.newBuilder().build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void validate_notBefore_success() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        RawJwt.newBuilder().setNotBefore(notBefore).build();
    String compact = mac.computeMacAndEncode(unverified);

    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = JwtValidator.newBuilder().setClock(clock2).build();
    VerifiedJwt token = mac.verifyMacAndDecode(compact, validator);

    assertThat(token.getNotBefore()).isEqualTo(notBefore.truncatedTo(MILLIS));
  }

  @Test
  public void validate_notBefore_clockSkew_success() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        RawJwt.newBuilder().setNotBefore(notBefore).build();
    String compact = mac.computeMacAndEncode(unverified);

    // A clock skew of 1 minute is allowed.
    JwtValidator validator = JwtValidator.newBuilder().setClockSkew(Duration.ofMinutes(1)).build();
    VerifiedJwt token = mac.verifyMacAndDecode(compact, validator);

    assertThat(token.getNotBefore()).isEqualTo(notBefore.truncatedTo(MILLIS));
  }

  @Test
  public void verify_noAudienceInJwt_shouldThrow() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    RawJwt unverified = RawJwt.newBuilder().build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().expectAudience("foo").build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void verify_noAudienceInValidator_shouldThrow() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    RawJwt unverified =
        RawJwt.newBuilder().addAudience("foo").build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void verify_wrongAudience_shouldThrow() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    RawJwt unverified =
        RawJwt.newBuilder().addAudience("foo").build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().expectAudience("bar").build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyMacAndDecode(compact, validator));
  }

  @Test
  public void verify_audience_success() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    RawJwt unverified =
        RawJwt.newBuilder().addAudience("foo").build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().expectAudience("foo").build();
    VerifiedJwt token = mac.verifyMacAndDecode(compact, validator);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void verify_multipleAudiences_success() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    JwtMac mac = handle.getPrimitive(JwtMac.class);

    RawJwt unverified =
        RawJwt.newBuilder()
            .addAudience("foo")
            .addAudience("bar")
            .build();
    String compact = mac.computeMacAndEncode(unverified);
    JwtValidator validator = JwtValidator.newBuilder().expectAudience("bar").build();
    VerifiedJwt token = mac.verifyMacAndDecode(compact, validator);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  private static String generateSignedCompact(PrfMac mac, JsonObject header, JsonObject payload)
      throws GeneralSecurityException {
    String payloadBase64 = Base64.urlSafeEncode(payload.toString().getBytes(UTF_8));
    String headerBase64 = Base64.urlSafeEncode(header.toString().getBytes(UTF_8));
    String unsignedCompact = headerBase64 + "." + payloadBase64;
    String signature = Base64.urlSafeEncode(mac.computeMac(unsignedCompact.getBytes(UTF_8)));
    return unsignedCompact + "." + signature;
  }

  @Test
  public void createSignVerify_withDifferentHeaders() throws Exception {
    KeyTemplate template = JwtHmacKeyManager.hs256Template();
    KeysetHandle handle = KeysetHandle.generateNew(template);
    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);
    JwtHmacKey keyProto =
        JwtHmacKey.parseFrom(
            keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    byte[] keyValue = keyProto.getKeyValue().toByteArray();
    SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
    PrfHmacJce prf = new PrfHmacJce("HMACSHA256", keySpec);
    PrfMac rawPrimitive = new PrfMac(prf, prf.getMaxOutputLength());
    JwtMac primitive = handle.getPrimitive(JwtMac.class);

    JsonObject payload = new JsonObject();
    payload.addProperty(JwtNames.CLAIM_JWT_ID, "jwtId");
    JwtValidator validator = JwtValidator.newBuilder().build();

    // Normal, valid signed compact.
    JsonObject normalHeader = new JsonObject();
    normalHeader.addProperty(JwtNames.HEADER_ALGORITHM, "HS256");
    String normalSignedCompact = generateSignedCompact(rawPrimitive, normalHeader, payload);
    primitive.verifyMacAndDecode(normalSignedCompact, validator);

    // valid token, with "typ" set in the header
    JsonObject goodHeader = new JsonObject();
    goodHeader.addProperty(JwtNames.HEADER_ALGORITHM, "HS256");
    goodHeader.addProperty("typ", "JWT");
    String goodSignedCompact = generateSignedCompact(rawPrimitive, goodHeader, payload);
    primitive.verifyMacAndDecode(
        goodSignedCompact, JwtValidator.newBuilder().expectTypeHeader("JWT").build());

    // invalid token with an empty header
    JsonObject emptyHeader = new JsonObject();
    String emptyHeaderSignedCompact = generateSignedCompact(rawPrimitive, emptyHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> primitive.verifyMacAndDecode(emptyHeaderSignedCompact, validator));

    // invalid token with a valid but incorrect algorithm in the header
    JsonObject badAlgoHeader = new JsonObject();
    badAlgoHeader.addProperty(JwtNames.HEADER_ALGORITHM, "RS256");
    String badAlgoSignedCompact = generateSignedCompact(rawPrimitive, badAlgoHeader, payload);
    assertThrows(
        GeneralSecurityException.class,
        () -> primitive.verifyMacAndDecode(badAlgoSignedCompact, validator));

    // token with an unknown "typ" in the header is valid
    JsonObject unknownTypeHeader = new JsonObject();
    unknownTypeHeader.addProperty(JwtNames.HEADER_ALGORITHM, "HS256");
    unknownTypeHeader.addProperty("typ", "unknown");
    String unknownTypeSignedCompact = generateSignedCompact(
        rawPrimitive, unknownTypeHeader, payload);
    primitive.verifyMacAndDecode(
        unknownTypeSignedCompact, JwtValidator.newBuilder().expectTypeHeader("unknown").build());

    // token with an unknown "kid" in the header is valid
    JsonObject unknownKidHeader = new JsonObject();
    unknownKidHeader.addProperty(JwtNames.HEADER_ALGORITHM, "HS256");
    unknownKidHeader.addProperty("kid", "unknown");
    String unknownKidSignedCompact = generateSignedCompact(
        rawPrimitive, unknownKidHeader, payload);
    primitive.verifyMacAndDecode(unknownKidSignedCompact, validator);
  }

  private static KeysetHandle getRfc7515ExampleKeysetHandle() throws Exception {
    String keyValue =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    JwtHmacKey key =
        JwtHmacKey.newBuilder()
            .setVersion(0)
            .setAlgorithm(JwtHmacAlgorithm.HS256)
            .setKeyValue(ByteString.copyFrom(Base64.urlSafeDecode(keyValue)))
            .build();
    KeyData keyData = KeyData.newBuilder()
          .setTypeUrl("type.googleapis.com/google.crypto.tink.JwtHmacKey")
          .setValue(key.toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
          .build();
    Keyset.Key keySetKey = Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setKeyId(123)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
    Keyset keyset = Keyset.newBuilder().addKey(keySetKey).setPrimaryKeyId(123).build();
    return CleartextKeysetHandle.fromKeyset(keyset);
  }

  // Test vectors copied from https://tools.ietf.org/html/rfc7515#appendix-A.1.
  @Test
  public void verify_rfc7515TestVector_shouldThrow() throws Exception {
    KeysetHandle handle = getRfc7515ExampleKeysetHandle();
    JwtMac primitive = handle.getPrimitive(JwtMac.class);

    // The sample token has expired since 2011-03-22.
    String compact =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
            + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
            + "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
            + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    JwtValidator validator = JwtValidator.newBuilder().build();
    assertThrows(JwtInvalidException.class, () -> primitive.verifyMacAndDecode(compact, validator));
  }

  // Test vectors copied from https://tools.ietf.org/html/rfc7515#appendix-A.1.
  @Test
  public void verify_rfc7515TestVector_fixedClock_success() throws Exception {
    KeysetHandle handle = getRfc7515ExampleKeysetHandle();
    JwtMac primitive = handle.getPrimitive(JwtMac.class);

    // The sample token has expired since 2011-03-22T18:43:00Z.
    String compact =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
            + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo"
            + "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
            + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // One minute earlier than the expiration time of the sample token.
    String instant = "2011-03-22T18:42:00Z";
    Clock clock = Clock.fixed(Instant.parse(instant), ZoneOffset.UTC);
    JwtValidator validator =
        JwtValidator.newBuilder()
            .expectTypeHeader("JWT")
            .expectIssuer("joe")
            .setClock(clock)
            .build();

    VerifiedJwt token = primitive.verifyMacAndDecode(compact, validator);

    assertThat(token.getIssuer()).isEqualTo("joe");
    assertThat(token.getBooleanClaim("http://example.com/is_root")).isTrue();
  }
}
