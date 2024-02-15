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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.signature.RsaSsaPkcs1Parameters;
import com.google.crypto.tink.signature.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code JwtRsaSsaPkcs11Verify}. It doesn't support key
 * generation.
 */
final class JwtRsaSsaPkcs1VerifyKeyManager {
  // Note: each algorithm defines not just the modulo size, but also the
  // hash length and salt length to use.
  // See https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5
  private static RsaSsaPkcs1Parameters.HashType hashTypeForAlgorithm(
      JwtRsaSsaPkcs1Parameters.Algorithm algorithm) throws GeneralSecurityException {
    if (algorithm.equals(JwtRsaSsaPkcs1Parameters.Algorithm.RS256)) {
      return RsaSsaPkcs1Parameters.HashType.SHA256;
    }
    if (algorithm.equals(JwtRsaSsaPkcs1Parameters.Algorithm.RS384)) {
      return RsaSsaPkcs1Parameters.HashType.SHA384;
    }
    if (algorithm.equals(JwtRsaSsaPkcs1Parameters.Algorithm.RS512)) {
      return RsaSsaPkcs1Parameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  @AccessesPartialKey
  static RsaSsaPkcs1PublicKey toRsaSsaPkcs1PublicKey(JwtRsaSsaPkcs1PublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1Parameters rsaSsaPkcs1Parameters =
        RsaSsaPkcs1Parameters.builder()
            .setModulusSizeBits(publicKey.getParameters().getModulusSizeBits())
            .setPublicExponent(publicKey.getParameters().getPublicExponent())
            .setHashType(hashTypeForAlgorithm(publicKey.getParameters().getAlgorithm()))
            .setVariant(RsaSsaPkcs1Parameters.Variant.NO_PREFIX)
            .build();
    return RsaSsaPkcs1PublicKey.builder()
        .setParameters(rsaSsaPkcs1Parameters)
        .setModulus(publicKey.getModulus())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPkcs1VerifyJce.create is immutable.
  static JwtPublicKeyVerify createFullPrimitive(
      com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPkcs1PublicKey rsaSsaPkcs1PublicKey = toRsaSsaPkcs1PublicKey(publicKey);
    final PublicKeyVerify verifier = RsaSsaPkcs1VerifyJce.create(rsaSsaPkcs1PublicKey);

    return new JwtPublicKeyVerify() {
      @Override
      public VerifiedJwt verifyAndDecode(String compact, JwtValidator validator)
          throws GeneralSecurityException {
        JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
        verifier.verify(parts.signatureOrMac, parts.unsignedCompact.getBytes(US_ASCII));
        JsonObject parsedHeader = JsonUtil.parseJson(parts.header);
        JwtFormat.validateHeader(
            parsedHeader,
            publicKey.getParameters().getAlgorithm().getStandardName(),
            publicKey.getKid(),
            publicKey.getParameters().allowKidAbsent());
        RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
        return validator.validate(token);
      }
    };
  }

  static final PrimitiveConstructor<
          com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PublicKey, JwtPublicKeyVerify>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtRsaSsaPkcs1VerifyKeyManager::createFullPrimitive,
              com.google.crypto.tink.jwt.JwtRsaSsaPkcs1PublicKey.class,
              JwtPublicKeyVerify.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";
  }

  private JwtRsaSsaPkcs1VerifyKeyManager() {}
}
