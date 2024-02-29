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

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.signature.internal.EcdsaProtoSerialization;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code EcdsaPrivateKey} keys and produces new instances of {@code
 * EcdsaSignJce}.
 */
public final class EcdsaSignKeyManager {
  private static final PrimitiveConstructor<EcdsaPrivateKey, PublicKeySign>
      PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              EcdsaSignJce::create, EcdsaPrivateKey.class, PublicKeySign.class);

  private static final PrimitiveConstructor<EcdsaPublicKey, PublicKeyVerify>
      PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              EcdsaVerifyJce::create, EcdsaPublicKey.class, PublicKeyVerify.class);

  private static final PrivateKeyManager<PublicKeySign> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(), PublicKeySign.class, com.google.crypto.tink.proto.EcdsaPrivateKey.parser());

  private static final KeyManager<PublicKeyVerify> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          EcdsaVerifyKeyManager.getKeyType(),
          PublicKeyVerify.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.EcdsaPublicKey.parser());

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  }

  @AccessesPartialKey
  private static EcdsaPrivateKey createKey(
      EcdsaParameters parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    KeyPair keyPair = EllipticCurves.generateKeyPair(parameters.getCurveType().toParameterSpec());
    ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();

    EcdsaPublicKey publicKey =
        EcdsaPublicKey.builder()
            .setParameters(parameters)
            .setIdRequirement(idRequirement)
            .setPublicPoint(pubKey.getW())
            .build();

    return EcdsaPrivateKey.builder()
        .setPublicKey(publicKey)
        .setPrivateValue(
            SecretBigInteger.fromBigInteger(privKey.getS(), InsecureSecretKeyAccess.get()))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<EcdsaParameters> KEY_CREATOR =
      EcdsaSignKeyManager::createKey;

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("ECDSA_P256", PredefinedSignatureParameters.ECDSA_P256);
    // This key template does not make sense because IEEE P1363 mandates a raw signature.
    // It is needed to maintain backward compatibility with SignatureKeyTemplates.
    result.put("ECDSA_P256_IEEE_P1363", PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363);
    result.put(
        "ECDSA_P256_RAW",
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build());
    // This key template is identical to ECDSA_P256_RAW.
    // It is needed to maintain backward compatibility with SignatureKeyTemplates.
    result.put(
        "ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX",
        PredefinedSignatureParameters.ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX);
    result.put("ECDSA_P384", PredefinedSignatureParameters.ECDSA_P384);
    result.put("ECDSA_P384_IEEE_P1363", PredefinedSignatureParameters.ECDSA_P384_IEEE_P1363);
    result.put(
        "ECDSA_P384_SHA512",
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA512)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build());
    result.put(
        "ECDSA_P384_SHA384",
        EcdsaParameters.builder()
            .setHashType(EcdsaParameters.HashType.SHA384)
            .setCurveType(EcdsaParameters.CurveType.NIST_P384)
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build());
    result.put("ECDSA_P521", PredefinedSignatureParameters.ECDSA_P521);
    result.put("ECDSA_P521_IEEE_P1363", PredefinedSignatureParameters.ECDSA_P521_IEEE_P1363);
        return Collections.unmodifiableMap(result);
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  /**
   * Registers the {@link EcdsaSignKeyManager} and the {@link EcdsaVerifyKeyManager} with the
   * registry, so that the the Ecdsa-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ECDSA in FIPS-mode, as BoringCrypto module is not available.");
    }
    EcdsaProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PUBLIC_KEY_SIGN_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PUBLIC_KEY_VERIFY_PRIMITIVE_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, EcdsaParameters.class);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPrivateKeyManager, FIPS, newKeyAllowed);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyPublicKeyManager, FIPS, false);
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
   */
  public static final KeyTemplate ecdsaP256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.DER)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.TINK)
                    .build()));
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
   */
  public static final KeyTemplate rawEcdsaP256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                EcdsaParameters.builder()
                    .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
                    .setCurveType(EcdsaParameters.CurveType.NIST_P256)
                    .setHashType(EcdsaParameters.HashType.SHA256)
                    .setVariant(EcdsaParameters.Variant.NO_PREFIX)
                    .build()));
  }

  private EcdsaSignKeyManager() {}
}
