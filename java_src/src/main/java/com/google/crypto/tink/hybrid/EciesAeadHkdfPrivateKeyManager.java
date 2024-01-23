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

package com.google.crypto.tink.hybrid;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code EciesAeadHkdfPrivateKey} keys and produces new instances of
 * {@code EciesAeadHkdfHybridDecrypt}.
 */
public final class EciesAeadHkdfPrivateKeyManager {
  private static final PrimitiveConstructor<EciesPrivateKey, HybridDecrypt>
      HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              EciesAeadHkdfHybridDecrypt::create, EciesPrivateKey.class, HybridDecrypt.class);

  private static final PrimitiveConstructor<EciesPublicKey, HybridEncrypt>
      HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              EciesAeadHkdfHybridEncrypt::create, EciesPublicKey.class, HybridEncrypt.class);

  private static final PrivateKeyManager<HybridDecrypt> legacyPrivateKeyManager =
      LegacyKeyManagerImpl.createPrivateKeyManager(
          getKeyType(),
          HybridDecrypt.class,
          com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey.parser());

  private static final KeyManager<HybridEncrypt> legacyPublicKeyManager =
      LegacyKeyManagerImpl.create(
          EciesAeadHkdfPublicKeyManager.getKeyType(),
          HybridEncrypt.class,
          KeyMaterialType.ASYMMETRIC_PUBLIC,
          com.google.crypto.tink.proto.EciesAeadHkdfPublicKey.parser());

  private static final ECParameterSpec toParameterSpec(EciesParameters.CurveType curveType)
      throws GeneralSecurityException {
    if (curveType == EciesParameters.CurveType.NIST_P256) {
      return EllipticCurvesUtil.NIST_P256_PARAMS;
    }
    if (curveType == EciesParameters.CurveType.NIST_P384) {
      return EllipticCurvesUtil.NIST_P384_PARAMS;
    }
    if (curveType == EciesParameters.CurveType.NIST_P521) {
      return EllipticCurvesUtil.NIST_P521_PARAMS;
    }
    throw new GeneralSecurityException("Unsupported curve type: " + curveType);
  }

  @AccessesPartialKey
  private static EciesPrivateKey createKey(
      EciesParameters parameters, @Nullable Integer idRequirement) throws GeneralSecurityException {
    // toParameterSpec throws for curve X25519
    KeyPair keyPair = EllipticCurves.generateKeyPair(toParameterSpec(parameters.getCurveType()));
    ECPublicKey ecPubKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey ecPrivKey = (ECPrivateKey) keyPair.getPrivate();

    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(parameters, ecPubKey.getW(), idRequirement);
    return EciesPrivateKey.createForNistCurve(
        publicKey,
        SecretBigInteger.fromBigInteger(ecPrivKey.getS(), InsecureSecretKeyAccess.get()));
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<EciesParameters> KEY_CREATOR =
      EciesAeadHkdfPrivateKeyManager::createKey;

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                .setVariant(EciesParameters.Variant.TINK)
                .setDemParameters(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_RAW",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.TINK)
                .setDemParameters(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM_RAW",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        // backward compatibility with HybridKeyTemplates
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                .setVariant(EciesParameters.Variant.TINK)
                .setDemParameters(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.TINK)
                .setDemParameters(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW",
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build());
        return Collections.unmodifiableMap(result);
  }

  /**
   * Registers the {@link EciesAeadHkdfPrivateKeyManager} and the {@link
   * EciesAeadHkdfPublicKeyManager} with the registry, so that the the EciesAeadHkdfKeys can be used
   * with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    EciesProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(HYBRID_DECRYPT_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(HYBRID_ENCRYPT_PRIMITIVE_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, EciesParameters.class);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyPrivateKeyManager, newKeyAllowed);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyPublicKeyManager, false);
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of ECIES-AEAD-HKDF key pairs with
   *     the following parameters:
   *     <ul>
   *       <li>KEM: ECDH over NIST P-256
   *       <li>DEM: AES128-GCM
   *       <li>KDF: HKDF-HMAC-SHA256 with an empty salt
   *       <li>EC Point Format: Uncompressed
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   *     <p>Unlike other key templates that use AES-GCM, the instances of {@link HybridDecrypt}
   *     generated by this key template has no limitation on Android KitKat (API level 19). They
   *     might not work in older versions though.
   */
  public static final KeyTemplate eciesP256HkdfHmacSha256Aes128GcmTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                EciesParameters.builder()
                    .setCurveType(EciesParameters.CurveType.NIST_P256)
                    .setHashType(EciesParameters.HashType.SHA256)
                    .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                    .setVariant(EciesParameters.Variant.TINK)
                    .setDemParameters(
                        AesGcmParameters.builder()
                            .setIvSizeBytes(12)
                            .setKeySizeBytes(16)
                            .setTagSizeBytes(16)
                            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                            .build())
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of ECIES-AEAD-HKDF key pairs with
   *     the following parameters:
   *     <ul>
   *       <li>KEM: ECDH over NIST P-256
   *       <li>DEM: AES128-GCM
   *       <li>KDF: HKDF-HMAC-SHA256 with an empty salt
   *       <li>EC Point Format: Compressed
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   *     <p>Unlike other key templates that use AES-GCM, the instances of {@link HybridDecrypt}
   *     generated by this key template has no limitation on Android KitKat (API level 19). They
   *     might not work in older versions though.
   */
  public static final KeyTemplate rawEciesP256HkdfHmacSha256Aes128GcmCompressedTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                EciesParameters.builder()
                    .setCurveType(EciesParameters.CurveType.NIST_P256)
                    .setHashType(EciesParameters.HashType.SHA256)
                    .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                    .setVariant(EciesParameters.Variant.NO_PREFIX)
                    .setDemParameters(
                        AesGcmParameters.builder()
                            .setIvSizeBytes(12)
                            .setKeySizeBytes(16)
                            .setTagSizeBytes(16)
                            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                            .build())
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of ECIES-AEAD-HKDF key pairs with
   *     the following parameters:
   *     <ul>
   *       <li>KEM: ECDH over NIST P-256
   *       <li>DEM: AES128-CTR-HMAC-SHA256 with the following parameters
   *           <ul>
   *             <li>AES key size: 16 bytes
   *             <li>AES CTR IV size: 16 bytes
   *             <li>HMAC key size: 32 bytes
   *             <li>HMAC tag size: 16 bytes
   *           </ul>
   *       <li>KDF: HKDF-HMAC-SHA256 with an empty salt
   *       <li>EC Point Format: Uncompressed
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate eciesP256HkdfHmacSha256Aes128CtrHmacSha256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                EciesParameters.builder()
                    .setCurveType(EciesParameters.CurveType.NIST_P256)
                    .setHashType(EciesParameters.HashType.SHA256)
                    .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                    .setVariant(EciesParameters.Variant.TINK)
                    .setDemParameters(
                        AesCtrHmacAeadParameters.builder()
                            .setAesKeySizeBytes(16)
                            .setHmacKeySizeBytes(32)
                            .setTagSizeBytes(16)
                            .setIvSizeBytes(16)
                            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                            .build())
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of ECIES-AEAD-HKDF key pairs with
   *     the following parameters:
   *     <ul>
   *       <li>KEM: ECDH over NIST P-256
   *       <li>DEM: AES128-CTR-HMAC-SHA256 with the following parameters
   *           <ul>
   *             <li>AES key size: 16 bytes
   *             <li>AES CTR IV size: 16 bytes
   *             <li>HMAC key size: 32 bytes
   *             <li>HMAC tag size: 16 bytes
   *           </ul>
   *       <li>KDF: HKDF-HMAC-SHA256 with an empty salt
   *       <li>EC Point Format: Compressed
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   */
  public static final KeyTemplate
      rawEciesP256HkdfHmacSha256Aes128CtrHmacSha256CompressedTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                EciesParameters.builder()
                    .setCurveType(EciesParameters.CurveType.NIST_P256)
                    .setHashType(EciesParameters.HashType.SHA256)
                    .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                    .setVariant(EciesParameters.Variant.NO_PREFIX)
                    .setDemParameters(
                        AesCtrHmacAeadParameters.builder()
                            .setAesKeySizeBytes(16)
                            .setHmacKeySizeBytes(32)
                            .setTagSizeBytes(16)
                            .setIvSizeBytes(16)
                            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                            .build())
                    .build()));
  }

  private EciesAeadHkdfPrivateKeyManager() {}
}
