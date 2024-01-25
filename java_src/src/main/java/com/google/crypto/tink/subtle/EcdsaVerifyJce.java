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

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.signature.EcdsaParameters;
import com.google.crypto.tink.signature.EcdsaPublicKey;
import com.google.crypto.tink.subtle.EllipticCurves.CurveType;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.List;

/**
 * ECDSA verifying with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaVerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final ECPublicKey publicKey;

  private final String signatureAlgorithm;
  private final EcdsaEncoding encoding;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  // This converter is not used with a proto but rather with an ordinary enum type.
  static final EnumTypeProtoConverter<HashType, EcdsaParameters.HashType> HASH_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HashType, EcdsaParameters.HashType>builder()
          .add(HashType.SHA256, EcdsaParameters.HashType.SHA256)
          .add(HashType.SHA384, EcdsaParameters.HashType.SHA384)
          .add(HashType.SHA512, EcdsaParameters.HashType.SHA512)
          .build();
  static final EnumTypeProtoConverter<EcdsaEncoding, EcdsaParameters.SignatureEncoding>
      ENCODING_CONVERTER =
          EnumTypeProtoConverter.<EcdsaEncoding, EcdsaParameters.SignatureEncoding>builder()
              .add(EcdsaEncoding.IEEE_P1363, EcdsaParameters.SignatureEncoding.IEEE_P1363)
              .add(EcdsaEncoding.DER, EcdsaParameters.SignatureEncoding.DER)
              .build();
  static final EnumTypeProtoConverter<CurveType, EcdsaParameters.CurveType> CURVE_TYPE_CONVERTER =
      EnumTypeProtoConverter.<CurveType, EcdsaParameters.CurveType>builder()
          .add(CurveType.NIST_P256, EcdsaParameters.CurveType.NIST_P256)
          .add(CurveType.NIST_P384, EcdsaParameters.CurveType.NIST_P384)
          .add(CurveType.NIST_P521, EcdsaParameters.CurveType.NIST_P521)
          .build();

  @AccessesPartialKey
  public static PublicKeyVerify create(EcdsaPublicKey key) throws GeneralSecurityException {
    ECPublicKey publicKey =
        EllipticCurves.getEcPublicKey(
            CURVE_TYPE_CONVERTER.toProtoEnum(key.getParameters().getCurveType()),
            key.getPublicPoint().getAffineX().toByteArray(),
            key.getPublicPoint().getAffineY().toByteArray());

    return new EcdsaVerifyJce(
        publicKey,
        HASH_TYPE_CONVERTER.toProtoEnum(key.getParameters().getHashType()),
        ENCODING_CONVERTER.toProtoEnum(key.getParameters().getSignatureEncoding()),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(EcdsaParameters.Variant.LEGACY)
            ? new byte[] {0}
            : new byte[0]);
  }

  private EcdsaVerifyJce(
      final ECPublicKey pubKey,
      HashType hash,
      EcdsaEncoding encoding,
      byte[] outputPrefix,
      byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ECDSA in FIPS-mode, as BoringCrypto is not available.");
    }

    EllipticCurves.checkPublicKey(pubKey);
    this.signatureAlgorithm = SubtleUtil.toEcdsaAlgo(hash);
    this.publicKey = pubKey;
    this.encoding = encoding;
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  public EcdsaVerifyJce(final ECPublicKey pubKey, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    this(pubKey, hash, encoding, new byte[0], new byte[0]);
  }

  private void noPrefixVerify(final byte[] signature, final byte[] data)
      throws GeneralSecurityException {
    byte[] derSignature = signature;
    if (encoding == EcdsaEncoding.IEEE_P1363) {
      EllipticCurve curve = publicKey.getParams().getCurve();
      if (signature.length != 2 * EllipticCurves.fieldSizeInBytes(curve)) {
        throw new GeneralSecurityException("Invalid signature");
      }
      derSignature = EllipticCurves.ecdsaIeee2Der(signature);
    }
    if (!EllipticCurves.isValidDerEncoding(derSignature)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    List<Provider> preferredProviders =
        EngineFactory.toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt");
    Signature verifier =
        EngineFactory.SIGNATURE.getInstance(signatureAlgorithm, preferredProviders);
    verifier.initVerify(publicKey);
    verifier.update(data);
    boolean verified = false;
    try {
      verified = verifier.verify(derSignature);
    } catch (java.lang.RuntimeException ex) {
      verified = false;
    }
    if (!verified) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (outputPrefix.length == 0 && messageSuffix.length == 0) {
      noPrefixVerify(signature, data);
      return;
    }
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    byte[] dataCopy = data;
    if (messageSuffix.length != 0) {
      dataCopy = Bytes.concat(data, messageSuffix);
    }
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
    noPrefixVerify(signatureNoPrefix, dataCopy);
  }
}
