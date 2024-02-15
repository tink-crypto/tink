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
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import com.google.gson.JsonObject;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code JwtRsaSsaPss1Verify}. It doesn't support key
 * generation.
 */
final class JwtRsaSsaPssVerifyKeyManager {
  private static RsaSsaPssParameters.HashType hashTypeForAlgorithm(
      JwtRsaSsaPssParameters.Algorithm algorithm) throws GeneralSecurityException {
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS256)) {
      return RsaSsaPssParameters.HashType.SHA256;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS384)) {
      return RsaSsaPssParameters.HashType.SHA384;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS512)) {
      return RsaSsaPssParameters.HashType.SHA512;
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  static final int saltLengthForPssAlgorithm(JwtRsaSsaPssParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS256)) {
      return 32;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS384)) {
      return 48;
    }
    if (algorithm.equals(JwtRsaSsaPssParameters.Algorithm.PS512)) {
      return 64;
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  @AccessesPartialKey
  static RsaSsaPssPublicKey toRsaSsaPssPublicKey(JwtRsaSsaPssPublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPssParameters rsaSsaPssParameters =
        RsaSsaPssParameters.builder()
            .setModulusSizeBits(publicKey.getParameters().getModulusSizeBits())
            .setPublicExponent(publicKey.getParameters().getPublicExponent())
            .setSigHashType(hashTypeForAlgorithm(publicKey.getParameters().getAlgorithm()))
            .setMgf1HashType(hashTypeForAlgorithm(publicKey.getParameters().getAlgorithm()))
            .setSaltLengthBytes(saltLengthForPssAlgorithm(publicKey.getParameters().getAlgorithm()))
            .setVariant(RsaSsaPssParameters.Variant.NO_PREFIX)
            .build();
    return RsaSsaPssPublicKey.builder()
        .setParameters(rsaSsaPssParameters)
        .setModulus(publicKey.getModulus())
        .build();
  }

  @SuppressWarnings("Immutable") // RsaSsaPssVerifyJce.create returns an immutable verifier.
  static JwtPublicKeyVerify createFullPrimitive(JwtRsaSsaPssPublicKey publicKey)
      throws GeneralSecurityException {
    RsaSsaPssPublicKey rsaSsaPssPublicKey = toRsaSsaPssPublicKey(publicKey);
    final PublicKeyVerify verifier = RsaSsaPssVerifyJce.create(rsaSsaPssPublicKey);

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

  static final PrimitiveConstructor<JwtRsaSsaPssPublicKey, JwtPublicKeyVerify>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              JwtRsaSsaPssVerifyKeyManager::createFullPrimitive,
              JwtRsaSsaPssPublicKey.class,
              JwtPublicKeyVerify.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";
  }

  private JwtRsaSsaPssVerifyKeyManager() {}
}
