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

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.proto.JwtHmacAlgorithm;
import com.google.crypto.tink.proto.JwtHmacKey;
import com.google.crypto.tink.proto.JwtHmacKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.errorprone.annotations.Immutable;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;

/**
 * This key manager generates new {@code JwtHmacKey} keys and produces new instances of {@link
 * JwtHmac}.
 */
public final class JwtHmacKeyManager extends KeyTypeManager<JwtHmacKey> {
  private static final String getAlgorithmName(JwtHmacAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case HS256:
        return "HS256";
      case HS384:
        return "HS384";
      case HS512:
        return "HS512";
      default:
        throw new GeneralSecurityException("unknown algorithm");
    }
  }

  private static final String getHmacAlgorithm(JwtHmacAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case HS256:
        return "HMACSHA256";
      case HS384:
        return "HMACSHA384";
      case HS512:
        return "HMACSHA512";
      default:
        throw new GeneralSecurityException("unknown algorithm");
    }
  }

  /** Returns the minimum key size in bytes.
   *
   * <p>These minimum key sizes are required by https://tools.ietf.org/html/rfc7518#section-3.2
   */
  private static final int getMinimumKeySizeInBytes(JwtHmacAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case HS256:
        return 32;
      case HS384:
        return 48;
      case HS512:
        return 64;
      default:
        throw new GeneralSecurityException("unknown algorithm");
    }
  }

  @Immutable
  private static final class JwtHmac implements JwtMacInternal {
    private final PrfMac prfMac;
    private final String algorithm;
    private final Optional<String> customKidFromHmacKey;

    public JwtHmac(String algorithm, Optional<String> customKidFromHmacKey, PrfMac prfMac) {
      this.algorithm = algorithm;
      this.customKidFromHmacKey = customKidFromHmacKey;
      this.prfMac = prfMac;
    }

    @Override
    public String computeMacAndEncodeWithKid(RawJwt rawJwt, Optional<String> kid)
        throws GeneralSecurityException {
      if (customKidFromHmacKey.isPresent()) {
        if (kid.isPresent()) {
          throw new JwtInvalidException("custom_kid can only be set for RAW keys.");
        }
        kid = customKidFromHmacKey;
      }
      String unsignedCompact = JwtFormat.createUnsignedCompact(algorithm, kid, rawJwt);
      return JwtFormat.createSignedCompact(
          unsignedCompact, prfMac.computeMac(unsignedCompact.getBytes(US_ASCII)));
    }

    @Override
    public VerifiedJwt verifyMacAndDecodeWithKid(
        String compact, JwtValidator validator, Optional<String> kid)
        throws GeneralSecurityException {
      JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
      prfMac.verifyMac(parts.signatureOrMac, parts.unsignedCompact.getBytes(US_ASCII));
      JsonObject parsedHeader = JsonUtil.parseJson(parts.header);
      JwtFormat.validateHeader(algorithm, kid, customKidFromHmacKey, parsedHeader);
      RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
      return validator.validate(token);
    }
  };

  public JwtHmacKeyManager() {
    super(
        JwtHmacKey.class,
        new PrimitiveFactory<JwtMacInternal, JwtHmacKey>(JwtMacInternal.class) {
          @Override
          public JwtMacInternal getPrimitive(JwtHmacKey key) throws GeneralSecurityException {
            JwtHmacAlgorithm algorithm = key.getAlgorithm();
            byte[] keyValue = key.getKeyValue().toByteArray();
            SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
            PrfHmacJce prf = new PrfHmacJce(getHmacAlgorithm(algorithm), keySpec);
            final PrfMac prfMac = new PrfMac(prf, prf.getMaxOutputLength());
            final Optional<String> customKid =
                key.hasCustomKid() ? Optional.of(key.getCustomKid().getValue()) : Optional.empty();
            return new JwtHmac(getAlgorithmName(algorithm), customKid, prfMac);
          }
        });
  }
  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtHmacKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(JwtHmacKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    if (key.getKeyValue().size() < getMinimumKeySizeInBytes(key.getAlgorithm())) {
      throw new GeneralSecurityException("key too short");
    }
  }

  @Override
  public JwtHmacKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return JwtHmacKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<JwtHmacKeyFormat, JwtHmacKey> keyFactory() {
    return new KeyFactory<JwtHmacKeyFormat, JwtHmacKey>(JwtHmacKeyFormat.class) {
      @Override
      public void validateKeyFormat(JwtHmacKeyFormat format) throws GeneralSecurityException {
        if (format.getKeySize() < getMinimumKeySizeInBytes(format.getAlgorithm())) {
          throw new GeneralSecurityException("key too short");
        }
      }

      @Override
      public JwtHmacKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return JwtHmacKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public JwtHmacKey createKey(JwtHmacKeyFormat format) {
        return JwtHmacKey.newBuilder()
            .setVersion(getVersion())
            .setAlgorithm(format.getAlgorithm())
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .build();
      }

      /**
       * List of default templates to generate tokens with algorithms "HS256", "HS384" or "HS512".
       * Use the template with the "_RAW" suffix if you want to generate tokens without a "kid"
       * header.
       */
      @Override
      public Map<String, KeyTemplate> namedKeyTemplates(String typeUrl)
          throws GeneralSecurityException {
        Map<String, KeyTemplate> result = new HashMap<>();
        result.put(
            "JWT_HS256_RAW",
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                    .build()));
        result.put(
            "JWT_HS256",
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .build()));
        result.put(
            "JWT_HS384_RAW",
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(48)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                    .build()));
        result.put(
            "JWT_HS384",
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(48)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS384)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .build()));
        result.put(
            "JWT_HS512_RAW",
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(64)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
                    .build()));
        result.put(
            "JWT_HS512",
            KeyTemplate.createFrom(
                JwtHmacParameters.builder()
                    .setKeySizeBytes(64)
                    .setAlgorithm(JwtHmacParameters.Algorithm.HS512)
                    .setKidStrategy(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)
                    .build()));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new JwtHmacKeyManager(), newKeyAllowed);
    JwtHmacProtoSerialization.register();
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

}
