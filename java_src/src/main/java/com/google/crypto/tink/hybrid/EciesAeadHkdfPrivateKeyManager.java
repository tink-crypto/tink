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

package com.google.crypto.tink.hybrid;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadDemParams;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
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
 * This key manager generates new {@code EciesAeadHkdfPrivateKey} keys and produces new instances of
 * {@code EciesAeadHkdfHybridDecrypt}.
 */
public final class EciesAeadHkdfPrivateKeyManager
    extends PrivateKeyTypeManager<EciesAeadHkdfPrivateKey, EciesAeadHkdfPublicKey> {
  EciesAeadHkdfPrivateKeyManager() {
    super(
        EciesAeadHkdfPrivateKey.class,
        EciesAeadHkdfPublicKey.class,
        new PrimitiveFactory<HybridDecrypt, EciesAeadHkdfPrivateKey>(HybridDecrypt.class) {
          @Override
          public HybridDecrypt getPrimitive(EciesAeadHkdfPrivateKey recipientKeyProto)
              throws GeneralSecurityException {
            EciesAeadHkdfParams eciesParams = recipientKeyProto.getPublicKey().getParams();
            EciesHkdfKemParams kemParams = eciesParams.getKemParams();

            ECPrivateKey recipientPrivateKey =
                EllipticCurves.getEcPrivateKey(
                    HybridUtil.toCurveType(kemParams.getCurveType()),
                    recipientKeyProto.getKeyValue().toByteArray());
            EciesAeadHkdfDemHelper demHelper =
                new RegistryEciesAeadHkdfDemHelper(eciesParams.getDemParams().getAeadDem());
            return new EciesAeadHkdfHybridDecrypt(
                recipientPrivateKey,
                kemParams.getHkdfSalt().toByteArray(),
                HybridUtil.toHmacAlgo(kemParams.getHkdfHashType()),
                HybridUtil.toPointFormatType(eciesParams.getEcPointFormat()),
                demHelper);
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public EciesAeadHkdfPublicKey getPublicKey(EciesAeadHkdfPrivateKey key)
      throws GeneralSecurityException {
    return key.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public EciesAeadHkdfPrivateKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return EciesAeadHkdfPrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(EciesAeadHkdfPrivateKey keyProto) throws GeneralSecurityException {
    if (keyProto.getKeyValue().isEmpty()) {
      throw new GeneralSecurityException("invalid ECIES private key");
    }
    Validators.validateVersion(keyProto.getVersion(), getVersion());
    HybridUtil.validate(keyProto.getPublicKey().getParams());
  }

  @Override
  public KeyTypeManager.KeyFactory<EciesAeadHkdfKeyFormat, EciesAeadHkdfPrivateKey> keyFactory() {
    return new KeyTypeManager.KeyFactory<EciesAeadHkdfKeyFormat, EciesAeadHkdfPrivateKey>(
        EciesAeadHkdfKeyFormat.class) {
      @Override
      public void validateKeyFormat(EciesAeadHkdfKeyFormat eciesKeyFormat)
          throws GeneralSecurityException {
        HybridUtil.validate(eciesKeyFormat.getParams());
      }

      @Override
      public EciesAeadHkdfKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return EciesAeadHkdfKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public EciesAeadHkdfPrivateKey createKey(EciesAeadHkdfKeyFormat eciesKeyFormat)
          throws GeneralSecurityException {
        EciesHkdfKemParams kemParams = eciesKeyFormat.getParams().getKemParams();
        KeyPair keyPair =
            EllipticCurves.generateKeyPair(HybridUtil.toCurveType(kemParams.getCurveType()));
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) keyPair.getPrivate();
        ECPoint w = pubKey.getW();

        // Creates EciesAeadHkdfPublicKey.
        EciesAeadHkdfPublicKey eciesPublicKey =
            EciesAeadHkdfPublicKey.newBuilder()
                .setVersion(getVersion())
                .setParams(eciesKeyFormat.getParams())
                .setX(ByteString.copyFrom(w.getAffineX().toByteArray()))
                .setY(ByteString.copyFrom(w.getAffineY().toByteArray()))
                .build();

        // Creates EciesAeadHkdfPrivateKey.
        return EciesAeadHkdfPrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(eciesPublicKey)
            .setKeyValue(ByteString.copyFrom(privKey.getS().toByteArray()))
            .build();
      }

      @Override
      public Map<String, KeyFactory.KeyFormat<EciesAeadHkdfKeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<EciesAeadHkdfKeyFormat>> result = new HashMap<>();
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.UNCOMPRESSED,
                KeyTemplates.get("AES128_GCM"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_RAW",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.UNCOMPRESSED,
                KeyTemplates.get("AES128_GCM"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.COMPRESSED,
                KeyTemplates.get("AES128_GCM"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM_RAW",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.COMPRESSED,
                KeyTemplates.get("AES128_GCM"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.RAW));
        // backward compatibility with HybridKeyTemplates
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_COMPRESSED_WITHOUT_PREFIX",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.COMPRESSED,
                KeyTemplates.get("AES128_GCM"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.UNCOMPRESSED,
                KeyTemplates.get("AES128_CTR_HMAC_SHA256"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.UNCOMPRESSED,
                KeyTemplates.get("AES128_CTR_HMAC_SHA256"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.COMPRESSED,
                KeyTemplates.get("AES128_CTR_HMAC_SHA256"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW",
            createKeyFormat(
                EllipticCurveType.NIST_P256,
                HashType.SHA256,
                EcPointFormat.COMPRESSED,
                KeyTemplates.get("AES128_CTR_HMAC_SHA256"),
                EMPTY_SALT,
                KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  /**
   * Registers the {@link EciesAeadHkdfPrivateKeyManager} and the {@link
   * EciesAeadHkdfPublicKeyManager} with the registry, so that the the EciesAeadHkdfKeys can be used
   * with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new EciesAeadHkdfPrivateKeyManager(), new EciesAeadHkdfPublicKeyManager(), newKeyAllowed);
    EciesProtoSerialization.register();
  }

  private static final byte[] EMPTY_SALT = new byte[0];

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

  private static KeyFactory.KeyFormat<EciesAeadHkdfKeyFormat> createKeyFormat(
      EllipticCurveType curve,
      HashType hashType,
      EcPointFormat ecPointFormat,
      KeyTemplate demKeyTemplate,
      byte[] salt,
      KeyTemplate.OutputPrefixType prefixType) {
    return new KeyFactory.KeyFormat<>(
        EciesAeadHkdfKeyFormat.newBuilder()
            .setParams(createParams(curve, hashType, ecPointFormat, demKeyTemplate, salt))
            .build(),
        prefixType);
  }

  /** @return a {@link EciesAeadHkdfParams} with the specified parameters. */
  static EciesAeadHkdfParams createParams(
      EllipticCurveType curve,
      HashType hashType,
      EcPointFormat ecPointFormat,
      KeyTemplate demKeyTemplate,
      byte[] salt) {
    EciesHkdfKemParams kemParams =
        EciesHkdfKemParams.newBuilder()
            .setCurveType(curve)
            .setHkdfHashType(hashType)
            .setHkdfSalt(ByteString.copyFrom(salt))
            .build();
    com.google.crypto.tink.proto.KeyTemplate protoKt =
        exceptionIsBug(() -> KeyTemplateProtoConverter.toProto(demKeyTemplate));
    EciesAeadDemParams demParams = EciesAeadDemParams.newBuilder().setAeadDem(protoKt).build();
    return EciesAeadHkdfParams.newBuilder()
        .setKemParams(kemParams)
        .setDemParams(demParams)
        .setEcPointFormat(ecPointFormat)
        .build();
  }
}
