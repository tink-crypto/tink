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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.proto.EcdsaKeyFormat;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.internal.SigUtil;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.SelfKeyTestValidators;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code EcdsaPrivateKey} keys and produces new instances of {@code
 * EcdsaSignJce}.
 */
public final class EcdsaSignKeyManager
    extends PrivateKeyTypeManager<EcdsaPrivateKey, EcdsaPublicKey> {
  EcdsaSignKeyManager() {
    super(
        EcdsaPrivateKey.class,
        EcdsaPublicKey.class,
        new KeyTypeManager.PrimitiveFactory<PublicKeySign, EcdsaPrivateKey>(PublicKeySign.class) {
          @Override
          public PublicKeySign getPrimitive(EcdsaPrivateKey key) throws GeneralSecurityException {
            ECPrivateKey privateKey =
                EllipticCurves.getEcPrivateKey(
                    SigUtil.toCurveType(key.getPublicKey().getParams().getCurve()),
                    key.getKeyValue().toByteArray());

            ECPublicKey publicKey =
                EllipticCurves.getEcPublicKey(
                    SigUtil.toCurveType(key.getPublicKey().getParams().getCurve()),
                    key.getPublicKey().getX().toByteArray(),
                    key.getPublicKey().getY().toByteArray());

            SelfKeyTestValidators.validateEcdsa(
                privateKey,
                publicKey,
                SigUtil.toHashType(key.getPublicKey().getParams().getHashType()),
                SigUtil.toEcdsaEncoding(key.getPublicKey().getParams().getEncoding()));

            return new EcdsaSignJce(
                privateKey,
                SigUtil.toHashType(key.getPublicKey().getParams().getHashType()),
                SigUtil.toEcdsaEncoding(key.getPublicKey().getParams().getEncoding()));
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public EcdsaPublicKey getPublicKey(EcdsaPrivateKey key) throws GeneralSecurityException {
    return key.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public EcdsaPrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return EcdsaPrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(EcdsaPrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), getVersion());
    SigUtil.validateEcdsaParams(privKey.getPublicKey().getParams());
  }

  @Override
  public KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey> keyFactory() {
    return new KeyFactory<EcdsaKeyFormat, EcdsaPrivateKey>(EcdsaKeyFormat.class) {
      @Override
      public void validateKeyFormat(EcdsaKeyFormat format) throws GeneralSecurityException {
        SigUtil.validateEcdsaParams(format.getParams());
      }

      @Override
      public EcdsaKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return EcdsaKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public EcdsaPrivateKey createKey(EcdsaKeyFormat format) throws GeneralSecurityException {
        EcdsaParams ecdsaParams = format.getParams();
        KeyPair keyPair =
            EllipticCurves.generateKeyPair(SigUtil.toCurveType(ecdsaParams.getCurve()));
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
        ECPoint w = pubKey.getW();

        // Creates EcdsaPublicKey.
        EcdsaPublicKey ecdsaPubKey =
            EcdsaPublicKey.newBuilder()
                .setVersion(getVersion())
                .setParams(ecdsaParams)
                .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
                .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
                .build();

        // Creates EcdsaPrivateKey.
        return EcdsaPrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(ecdsaPubKey)
            .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<EcdsaKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<EcdsaKeyFormat>> result = new HashMap<>();
        result.put(
            "ECDSA_P256",
            createKeyFormat(
                HashType.SHA256,
                EllipticCurveType.NIST_P256,
                EcdsaSignatureEncoding.DER,
                KeyTemplate.OutputPrefixType.TINK));
        // This key template does not make sense because IEEE P1363 mandates a raw signature.
        // It is needed to maintain backward compatibility with SignatureKeyTemplates.
        // TODO(b/185475349): remove this in 2.0.0.
        result.put(
            "ECDSA_P256_IEEE_P1363",
            createKeyFormat(
                HashType.SHA256,
                EllipticCurveType.NIST_P256,
                EcdsaSignatureEncoding.IEEE_P1363,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECDSA_P256_RAW",
            createKeyFormat(
                HashType.SHA256,
                EllipticCurveType.NIST_P256,
                // Using IEEE_P1363 because a raw signature is a concatenation of r and s.
                EcdsaSignatureEncoding.IEEE_P1363,
                KeyTemplate.OutputPrefixType.RAW));
        // This key template is identical to ECDSA_P256_RAW.
        // It is needed to maintain backward compatibility with SignatureKeyTemplates.
        // TODO(b/185475349): remove this in 2.0.0.
        result.put(
            "ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX",
            createKeyFormat(
                HashType.SHA256,
                EllipticCurveType.NIST_P256,
                // Using IEEE_P1363 because a raw signature is a concatenation of r and s.
                EcdsaSignatureEncoding.IEEE_P1363,
                KeyTemplate.OutputPrefixType.RAW));
        // TODO(b/140101381): This template is confusing and will be removed.
        result.put(
            "ECDSA_P384",
            createKeyFormat(
                HashType.SHA512,
                EllipticCurveType.NIST_P384,
                EcdsaSignatureEncoding.DER,
                KeyTemplate.OutputPrefixType.TINK));
        // TODO(b/185475349): remove this in 2.0.0.
        result.put(
            "ECDSA_P384_IEEE_P1363",
            createKeyFormat(
                HashType.SHA512,
                EllipticCurveType.NIST_P384,
                EcdsaSignatureEncoding.IEEE_P1363,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECDSA_P384_SHA512",
            createKeyFormat(
                HashType.SHA512,
                EllipticCurveType.NIST_P384,
                EcdsaSignatureEncoding.DER,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECDSA_P384_SHA384",
            createKeyFormat(
                HashType.SHA384,
                EllipticCurveType.NIST_P384,
                EcdsaSignatureEncoding.DER,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECDSA_P521",
            createKeyFormat(
                HashType.SHA512,
                EllipticCurveType.NIST_P521,
                EcdsaSignatureEncoding.DER,
                KeyTemplate.OutputPrefixType.TINK));
        // TODO(b/185475349): remove this in 2.0.0.
        result.put(
            "ECDSA_P521_IEEE_P1363",
            createKeyFormat(
                HashType.SHA512,
                EllipticCurveType.NIST_P521,
                EcdsaSignatureEncoding.IEEE_P1363,
                KeyTemplate.OutputPrefixType.TINK));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  @Override
  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
  };

  /**
   * Registers the {@link EcdsaSignKeyManager} and the {@link EcdsaVerifyKeyManager} with the
   * registry, so that the the Ecdsa-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new EcdsaSignKeyManager(), new EcdsaVerifyKeyManager(), newKeyAllowed);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of ECDSA keys with the following
   *     parameters:
   *     <ul>
   *       <li>Hash function: SHA256
   *       <li>Curve: NIST P-256
   *       <li>Signature encoding: DER (this is the encoding that Java uses).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}.
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("ECDSA_P256")}
   */
  @Deprecated
  public static final KeyTemplate ecdsaP256Template() {
    return createKeyTemplate(
        HashType.SHA256,
        EllipticCurveType.NIST_P256,
        EcdsaSignatureEncoding.DER,
        KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of ECDSA keys with the following
   *     parameters:
   *     <ul>
   *       <li>Hash function: SHA256
   *       <li>Curve: NIST P-256
   *       <li>Signature encoding: DER (this is the encoding that Java uses).
   *       <li>Prefix type: RAW (no prefix).
   *     </ul>
   *     Keys generated from this template create raw signatures of exactly 64 bytes. It is
   *     compatible with JWS and most other libraries.
   * @deprecated use {@code KeyTemplates.get("ECDSA_P256_RAW")}
   */
  @Deprecated
  public static final KeyTemplate rawEcdsaP256Template() {
    return createKeyTemplate(
        HashType.SHA256,
        EllipticCurveType.NIST_P256,
        EcdsaSignatureEncoding.IEEE_P1363,
        KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link EcdsaKeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createKeyTemplate(
      HashType hashType,
      EllipticCurveType curve,
      EcdsaSignatureEncoding encoding,
      KeyTemplate.OutputPrefixType prefixType) {
    EcdsaParams params =
        EcdsaParams.newBuilder()
            .setHashType(hashType)
            .setCurve(curve)
            .setEncoding(encoding)
            .build();
    EcdsaKeyFormat format = EcdsaKeyFormat.newBuilder().setParams(params).build();
    return KeyTemplate.create(
        new EcdsaSignKeyManager().getKeyType(), format.toByteArray(), prefixType);
  }

  private static KeyFactory.KeyFormat<EcdsaKeyFormat> createKeyFormat(
      HashType hashType,
      EllipticCurveType curve,
      EcdsaSignatureEncoding encoding,
      KeyTemplate.OutputPrefixType prefixType) {
    EcdsaParams params =
        EcdsaParams.newBuilder()
            .setHashType(hashType)
            .setCurve(curve)
            .setEncoding(encoding)
            .build();
    EcdsaKeyFormat format = EcdsaKeyFormat.newBuilder().setParams(params).build();
    return new KeyFactory.KeyFormat<>(format, prefixType);
  }
}
