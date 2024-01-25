// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPrivateKey;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EllipticCurve;
import java.util.List;

/**
 * ECDSA signing with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaSignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final ECPrivateKey privateKey;

  private final String signatureAlgorithm;
  private final EcdsaEncoding encoding;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  private EcdsaSignJce(
      final ECPrivateKey priv,
      HashType hash,
      EcdsaEncoding encoding,
      byte[] outputPrefix,
      byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ECDSA in FIPS-mode, as BoringCrypto is not available.");
    }

    this.privateKey = priv;
    this.signatureAlgorithm = SubtleUtil.toEcdsaAlgo(hash);
    this.encoding = encoding;
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  public EcdsaSignJce(final ECPrivateKey priv, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    this(priv, hash, encoding, new byte[0], new byte[0]);
  }

  @AccessesPartialKey
  public static PublicKeySign create(EcdsaPrivateKey key) throws GeneralSecurityException {
    HashType hashType =
        EcdsaVerifyJce.HASH_TYPE_CONVERTER.toProtoEnum(key.getParameters().getHashType());
    EcdsaEncoding ecdsaEncoding =
        EcdsaVerifyJce.ENCODING_CONVERTER.toProtoEnum(key.getParameters().getSignatureEncoding());
    CurveType curveType =
        EcdsaVerifyJce.CURVE_TYPE_CONVERTER.toProtoEnum(key.getParameters().getCurveType());

    ECPrivateKey privateKey =
        EllipticCurves.getEcPrivateKey(
            curveType,
            key.getPrivateValue().getBigInteger(InsecureSecretKeyAccess.get()).toByteArray());

    PublicKeySign signer =
        new EcdsaSignJce(
            privateKey,
            hashType,
            ecdsaEncoding,
            key.getOutputPrefix().toByteArray(),
            key.getParameters().getVariant().equals(EcdsaParameters.Variant.LEGACY)
                ? new byte[] {0}
                : new byte[0]);
    PublicKeyVerify verify = EcdsaVerifyJce.create(key.getPublicKey());
    try {
      verify.verify(signer.sign(new byte[] {1, 2, 3}), new byte[] {1, 2, 3});
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException(
          "ECDSA signing with private key followed by verifying with public key failed."
              + " The key may be corrupted.",
          e);
    }
    return signer;
  }

  private byte[] noPrefixSign(final byte[] data) throws GeneralSecurityException {
    // Prefer Conscrypt over other providers if available.
    List<Provider> preferredProviders =
        EngineFactory.toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt");
    Signature signer = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm, preferredProviders);
    signer.initSign(privateKey);
    signer.update(data);
    byte[] signature = signer.sign();
    if (encoding == EcdsaEncoding.IEEE_P1363) {
      EllipticCurve curve = privateKey.getParams().getCurve();
      signature =
          EllipticCurves.ecdsaDer2Ieee(signature, 2 * EllipticCurves.fieldSizeInBytes(curve));
    }
    return signature;
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    byte[] signature;
    if (messageSuffix.length == 0) {
      signature = noPrefixSign(data);
    } else {
      signature = noPrefixSign(Bytes.concat(data, messageSuffix));
    }
    if (outputPrefix.length == 0) {
      return signature;
    } else {
      return Bytes.concat(outputPrefix, signature);
    }
  }
}
