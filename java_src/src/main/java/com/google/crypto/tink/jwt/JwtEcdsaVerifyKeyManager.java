// Copyright 2017 Google LLC
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
import com.google.crypto.tink.proto.JwtEcdsaAlgorithm;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Enums;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code JwtEcdsaVerify}. It doesn't support key
 * generation.
 */
class JwtEcdsaVerifyKeyManager {
  static EcdsaParameters.CurveType getCurveType(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.CurveType.NIST_P256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.CurveType.NIST_P384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  static EcdsaParameters.HashType getHash(JwtEcdsaParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES256)) {
      return EcdsaParameters.HashType.SHA256;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES384)) {
      return EcdsaParameters.HashType.SHA384;
    }
    if (parameters.getAlgorithm().equals(JwtEcdsaParameters.Algorithm.ES512)) {
      return EcdsaParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm in parameters: " + parameters);
  }

  @AccessesPartialKey
  static EcdsaPublicKey toEcdsaPublicKey(com.google.crypto.tink.jwt.JwtEcdsaPublicKey publicKey)
      throws GeneralSecurityException {
    EcdsaParameters ecdsaParameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(getCurveType(publicKey.getParameters()))
            .setHashType(getHash(publicKey.getParameters()))
            .build();
    return EcdsaPublicKey.builder()
        .setParameters(ecdsaParameters)
        .setPublicPoint(publicKey.getPublicPoint())
        .build();
  }

  @SuppressWarnings("Immutable") // EcdsaVerifyJce.create returns an immutable verifier.
  static JwtPublicKeyVerify createFullPrimitive(
      com.google.crypto.tink.jwt.JwtEcdsaPublicKey publicKey) throws GeneralSecurityException {
    EcdsaPublicKey ecdsaPublicKey = toEcdsaPublicKey(publicKey);
    final PublicKeyVerify verifier = EcdsaVerifyJce.create(ecdsaPublicKey);

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
          com.google.crypto.tink.jwt.JwtEcdsaPublicKey, JwtPublicKeyVerify>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtEcdsaVerifyKeyManager::createFullPrimitive,
              com.google.crypto.tink.jwt.JwtEcdsaPublicKey.class,
              JwtPublicKeyVerify.class);

  static final EllipticCurves.CurveType getCurve(JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case ES256:
        return EllipticCurves.CurveType.NIST_P256;
      case ES384:
        return EllipticCurves.CurveType.NIST_P384;
      case ES512:
        return EllipticCurves.CurveType.NIST_P521;
      default:
        throw new GeneralSecurityException("unknown algorithm " + algorithm.name());
    }
  }

  public static Enums.HashType hashForEcdsaAlgorithm(JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case ES256:
        return Enums.HashType.SHA256;
      case ES384:
        return Enums.HashType.SHA384;
      case ES512:
        return Enums.HashType.SHA512;
      default:
        throw new GeneralSecurityException("unknown algorithm " + algorithm.name());
    }
  }

  static final void validateEcdsaAlgorithm(JwtEcdsaAlgorithm algorithm)
      throws GeneralSecurityException {
    // Purposely ignore the result. This function will throw if the algorithm is invalid.
    Object unused = hashForEcdsaAlgorithm(algorithm);
  }

  private JwtEcdsaVerifyKeyManager() {}

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
  }

}
