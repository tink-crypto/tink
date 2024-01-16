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
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * This key manager produces new instances of {@code JwtEcdsaVerify}. It doesn't support key
 * generation.
 */
final class JwtEcdsaVerifyKeyManager {
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
  static EcdsaPublicKey toEcdsaPublicKey(JwtEcdsaPublicKey publicKey)
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
  static JwtPublicKeyVerifyInternal getPrimitive(JwtEcdsaPublicKey publicKey)
      throws GeneralSecurityException {
    EcdsaPublicKey ecdsaPublicKey = toEcdsaPublicKey(publicKey);
    final PublicKeyVerify verifier = EcdsaVerifyJce.create(ecdsaPublicKey);

    return new JwtPublicKeyVerifyInternal() {
      @Override
      public VerifiedJwt verifyAndDecodeWithKid(
          String compact, JwtValidator validator, Optional<String> kid)
          throws GeneralSecurityException {
        JwtFormat.Parts parts = JwtFormat.splitSignedCompact(compact);
        verifier.verify(parts.signatureOrMac, parts.unsignedCompact.getBytes(US_ASCII));
        JsonObject parsedHeader = JsonUtil.parseJson(parts.header);
        JwtFormat.validateHeader(
            publicKey.getParameters().getAlgorithm().toString(),
            kid,
            publicKey.getKid(),
            parsedHeader);
        RawJwt token = RawJwt.fromJsonPayload(JwtFormat.getTypeHeader(parsedHeader), parts.payload);
        return validator.validate(token);
      }
    };
  }

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
  }

  private JwtEcdsaVerifyKeyManager() {}
}
