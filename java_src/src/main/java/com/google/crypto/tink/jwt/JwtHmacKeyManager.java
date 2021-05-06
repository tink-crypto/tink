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

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.Registry;
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
import java.io.InputStream;
import java.security.GeneralSecurityException;
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

  @Immutable
  private static final class JwtHmac implements JwtMac {
    private final PrfMac prfMac;
    private final String algorithm;

    public JwtHmac(String algorithm, PrfMac prfMac) {
      this.algorithm = algorithm;
      this.prfMac = prfMac;
    }

    @Override
    public String computeMacAndEncode(RawJwt rawJwt) throws GeneralSecurityException {
      String jsonPayload = rawJwt.getJsonPayload();
      Optional<String> typeHeader =
          rawJwt.hasTypeHeader() ? Optional.of(rawJwt.getTypeHeader()) : Optional.empty();
      String unsignedCompact = JwtFormat.createUnsignedCompact(algorithm, typeHeader, jsonPayload);
      return JwtFormat.createSignedCompact(
          unsignedCompact, prfMac.computeMac(unsignedCompact.getBytes(US_ASCII)));
    }

    @Override
    public VerifiedJwt verifyMacAndDecode(String compact, JwtValidator validator)
        throws GeneralSecurityException {
      JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
      prfMac.verifyMac(parts.signatureOrMac, parts.unsignedCompact.getBytes(US_ASCII));
      JsonObject parsedHeader = JwtFormat.parseJson(parts.header);
      JwtFormat.validateHeader(algorithm, parsedHeader);
      RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
      return validator.validate(token);
    }
  };

  public JwtHmacKeyManager() {
    super(
        JwtHmacKey.class,
        new PrimitiveFactory<JwtMac, JwtHmacKey>(JwtMac.class) {
          @Override
          public JwtMac getPrimitive(JwtHmacKey key) throws GeneralSecurityException {
            JwtHmacAlgorithm algorithm = key.getAlgorithm();
            byte[] keyValue = key.getKeyValue().toByteArray();
            SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
            PrfHmacJce prf = new PrfHmacJce(getHmacAlgorithm(algorithm), keySpec);
            final PrfMac prfMac = new PrfMac(prf, prf.getMaxOutputLength());
            return new JwtHmac(getAlgorithmName(algorithm), prfMac);
          }
        });
  }

  /** Minimum key size in bytes. */
  private static final int MIN_KEY_SIZE_IN_BYTES = 32;

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
    if (key.getKeyValue().size() < MIN_KEY_SIZE_IN_BYTES) {
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
        if (format.getKeySize() < MIN_KEY_SIZE_IN_BYTES) {
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

      @Override
      public JwtHmacKey deriveKey(JwtHmacKeyFormat format, InputStream inputStream)
          throws GeneralSecurityException {
        throw new UnsupportedOperationException();
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new JwtHmacKeyManager(), newKeyAllowed);
  }

  /** Returns a {@link KeyTemplate} that generates new instances of HS256 256-bit keys. */
  public static final KeyTemplate hs256Template() {
    return createTemplate(32, JwtHmacAlgorithm.HS256);
  }

  /** Returns a {@link KeyTemplate} that generates new instances of HS384 384-bit keys. */
  public static final KeyTemplate hs384Template() {
    return createTemplate(48, JwtHmacAlgorithm.HS384);
  }

  /** Returns a {@link KeyTemplate} that generates new instances of HS512 384-bit keys. */
  public static final KeyTemplate hs512Template() {
    return createTemplate(64, JwtHmacAlgorithm.HS512);
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link JwtHmacKeyFormat} with some specified
   *     parameters.
   */
  private static KeyTemplate createTemplate(int keySize, JwtHmacAlgorithm algorithm) {
    JwtHmacKeyFormat format =
        JwtHmacKeyFormat.newBuilder().setAlgorithm(algorithm).setKeySize(keySize).build();
    return KeyTemplate.create(
        new JwtHmacKeyManager().getKeyType(),
        format.toByteArray(),
        KeyTemplate.OutputPrefixType.RAW);
  }
}
