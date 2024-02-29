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

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.TinkBugException;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code JwtHmacKey} keys and produces new instances of {@link
 * JwtHmac}.
 */
public final class JwtHmacKeyManager {
  @Immutable
  private static final class JwtHmac implements JwtMac {
    @SuppressWarnings("Immutable") // Mac objects obtained from PrfMac.create are immutable.
    private final Mac mac;

    private final String algorithm;
    private final JwtHmacKey jwtHmacKey;

    private JwtHmac(Mac plainMac, JwtHmacKey jwtHmacKey) {
      this.algorithm = jwtHmacKey.getParameters().getAlgorithm().getStandardName();
      this.mac = plainMac;
      this.jwtHmacKey = jwtHmacKey;
    }

    @Override
    public String computeMacAndEncode(RawJwt rawJwt) throws GeneralSecurityException {
      String unsignedCompact =
          JwtFormat.createUnsignedCompact(algorithm, jwtHmacKey.getKid(), rawJwt);
      return JwtFormat.createSignedCompact(
          unsignedCompact, mac.computeMac(unsignedCompact.getBytes(US_ASCII)));
    }

    @Override
    public VerifiedJwt verifyMacAndDecode(String compact, JwtValidator validator)
        throws GeneralSecurityException {
      JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
      mac.verifyMac(parts.signatureOrMac, parts.unsignedCompact.getBytes(US_ASCII));
      JsonObject parsedHeader = JsonUtil.parseJson(parts.header);
      JwtFormat.validateHeader(
          parsedHeader,
          jwtHmacKey.getParameters().getAlgorithm().getStandardName(),
          jwtHmacKey.getKid(),
          jwtHmacKey.getParameters().allowKidAbsent());
      RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
      return validator.validate(token);
    }
  }

  private static void validate(JwtHmacParameters parameters) throws GeneralSecurityException {
    int minKeySize = Integer.MAX_VALUE;
    if (parameters.getAlgorithm().equals(JwtHmacParameters.Algorithm.HS256)) {
      minKeySize = 32;
    }
    if (parameters.getAlgorithm().equals(JwtHmacParameters.Algorithm.HS384)) {
      minKeySize = 48;
    }
    if (parameters.getAlgorithm().equals(JwtHmacParameters.Algorithm.HS512)) {
      minKeySize = 64;
    }
    if (parameters.getKeySizeBytes() < minKeySize) {
      throw new GeneralSecurityException("Key size must be at least " + minKeySize);
    }
  }

  private static int getTagLength(JwtHmacParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS256)) {
      return 32;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS384)) {
      return 48;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS512)) {
      return 64;
    }
    throw new GeneralSecurityException("Unsupported algorithm: " + algorithm);
  }

  private static HmacParameters.HashType getHmacHashType(JwtHmacParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS256)) {
      return HmacParameters.HashType.SHA256;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS384)) {
      return HmacParameters.HashType.SHA384;
    }
    if (algorithm.equals(JwtHmacParameters.Algorithm.HS512)) {
      return HmacParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("Unsupported algorithm: " + algorithm);
  }

  private static final KeyManager<JwtMac> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          "type.googleapis.com/google.crypto.tink.JwtHmacKey",
          JwtMac.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.JwtHmacKey.parser());

  @AccessesPartialKey
  private static JwtMac createFullJwtHmac(JwtHmacKey key) throws GeneralSecurityException {
    validate(key.getParameters());
    HmacKey hmacKey =
        HmacKey.builder()
            .setParameters(
                HmacParameters.builder()
                    .setKeySizeBytes(key.getParameters().getKeySizeBytes())
                    .setHashType(getHmacHashType(key.getParameters().getAlgorithm()))
                    .setTagSizeBytes(getTagLength(key.getParameters().getAlgorithm()))
                    .build())
            .setKeyBytes(key.getKeyBytes())
            .build();
    return new JwtHmac(PrfMac.create(hmacKey), key);
  }

  private static final PrimitiveConstructor<JwtHmacKey, JwtMac> PRIMITIVE_CONSTRUCTOR =
      PrimitiveConstructor.create(
          JwtHmacKeyManager::createFullJwtHmac, JwtHmacKey.class, JwtMac.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtHmacKey";
  }

  @AccessesPartialKey
  private static JwtHmacKey createKey(JwtHmacParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validate(parameters);
    JwtHmacKey.Builder builder =
        JwtHmacKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()));
    if (parameters.hasIdRequirement()) {
      builder.setIdRequirement(idRequirement);
    }
    return builder.build();
  }

  private static final MutableKeyCreationRegistry.KeyCreator<JwtHmacParameters> KEY_CREATOR =
      JwtHmacKeyManager::createKey;

  /**
   * List of default templates to generate tokens with algorithms "HS256", "HS384" or "HS512". Use
   * the template with the "_RAW" suffix if you want to generate tokens without a "kid" header.
   */
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "JWT_HS256_RAW",
            JwtHmacParameters.builder()
                .setKeySizeBytes(32)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
                .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_HS256",
            JwtHmacParameters.builder()
                .setKeySizeBytes(32)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
                .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        result.put(
            "JWT_HS384_RAW",
            JwtHmacParameters.builder()
                .setKeySizeBytes(48)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
                .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_HS384",
            JwtHmacParameters.builder()
                .setKeySizeBytes(48)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
                .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        result.put(
            "JWT_HS512_RAW",
            JwtHmacParameters.builder()
                .setKeySizeBytes(64)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
                .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                .build());
        result.put(
            "JWT_HS512",
            JwtHmacParameters.builder()
                .setKeySizeBytes(64)
                .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
                .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                .build());
        return Collections.unmodifiableMap(result);
  }

  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return FIPS;
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use HMAC in FIPS-mode, as BoringCrypto module is not available.");
    }
    JwtHmacProtoSerialization.register();
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, JwtHmacParameters.class);
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveConstructor(PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    try {
      KeyManagerRegistry.globalInstance()
          .registerKeyManagerWithFipsCompatibility(legacyKeyManager, FIPS, newKeyAllowed);
    } catch (GeneralSecurityException e) {
      throw new TinkBugException("JwtHmacKeyManager registration failed unexpectedly", e);
    }
  }

  /** Returns a {@link KeyTemplate} that generates new instances of HS256 256-bit keys. */
  public static final KeyTemplate hs256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
                    .build()));
  }

  /** Returns a {@link KeyTemplate} that generates new instances of HS384 384-bit keys. */
  public static final KeyTemplate hs384Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(48)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
                    .build()));
  }

  /** Returns a {@link KeyTemplate} that generates new instances of HS512 512-bit keys. */
  public static final KeyTemplate hs512Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(64)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
                    .build()));
  }

  private JwtHmacKeyManager() {}
}
