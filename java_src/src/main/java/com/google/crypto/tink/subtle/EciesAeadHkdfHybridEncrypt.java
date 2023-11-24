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
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.daead.AesSivKey;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.hybrid.EciesParameters;
import com.google.crypto.tink.hybrid.EciesPublicKey;
import com.google.crypto.tink.hybrid.subtle.AeadOrDaead;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * ECIES encryption with HKDF-KEM (key encapsulation mechanism) and AEAD-DEM (data
 * encapsulation mechanism).
 *
 * @since 1.0.0
 */
public final class EciesAeadHkdfHybridEncrypt implements HybridEncrypt {
  private static final byte[] EMPTY_AAD = new byte[0];
  private final EciesHkdfSenderKem senderKem;
  private final String hkdfHmacAlgo;
  private final byte[] hkdfSalt;
  private final EllipticCurves.PointFormatType ecPointFormat;
  private final EciesAeadHkdfDemHelper demHelper;
  private final byte[] outputPrefix;

  private static EciesAeadHkdfDemHelper createHelperAesGcm(AesGcmParameters parameters) {
    return new EciesAeadHkdfDemHelper() {
      @Override
      public int getSymmetricKeySizeInBytes() {
        return parameters.getKeySizeBytes();
      }

      @Override
      @AccessesPartialKey
      public AeadOrDaead getAeadOrDaead(final byte[] symmetricKeyValue)
          throws GeneralSecurityException {
        return new AeadOrDaead(
            AesGcmJce.create(
                AesGcmKey.builder()
                    .setParameters(parameters)
                    .setKeyBytes(
                        SecretBytes.copyFrom(symmetricKeyValue, InsecureSecretKeyAccess.get()))
                    .build()));
      }
    };
  }

  private static EciesAeadHkdfDemHelper createHelperAesCtrHmac(
      AesCtrHmacAeadParameters parameters) {
    return new EciesAeadHkdfDemHelper() {
      @Override
      public int getSymmetricKeySizeInBytes() {
        return parameters.getAesKeySizeBytes() + parameters.getHmacKeySizeBytes();
      }

      @Override
      @AccessesPartialKey
      public AeadOrDaead getAeadOrDaead(final byte[] symmetricKeyValue)
          throws GeneralSecurityException {
        byte[] aesCtrKeyValue =
            Arrays.copyOfRange(symmetricKeyValue, 0, parameters.getAesKeySizeBytes());
        byte[] hmacKeyValue =
            Arrays.copyOfRange(
                symmetricKeyValue,
                parameters.getAesKeySizeBytes(),
                parameters.getAesKeySizeBytes() + parameters.getHmacKeySizeBytes());
        return new AeadOrDaead(
            EncryptThenAuthenticate.create(
                AesCtrHmacAeadKey.builder()
                    .setParameters(parameters)
                    .setAesKeyBytes(
                        SecretBytes.copyFrom(aesCtrKeyValue, InsecureSecretKeyAccess.get()))
                    .setHmacKeyBytes(
                        SecretBytes.copyFrom(hmacKeyValue, InsecureSecretKeyAccess.get()))
                    .build()));
      }
    };
  }

  private static EciesAeadHkdfDemHelper createHelperAesSiv(AesSivParameters parameters) {
    return new EciesAeadHkdfDemHelper() {
      @Override
      public int getSymmetricKeySizeInBytes() {
        return parameters.getKeySizeBytes();
      }

      @Override
      @AccessesPartialKey
      public AeadOrDaead getAeadOrDaead(final byte[] symmetricKeyValue)
          throws GeneralSecurityException {
        return new AeadOrDaead(
            AesSiv.create(
                AesSivKey.builder()
                    .setParameters(parameters)
                    .setKeyBytes(
                        SecretBytes.copyFrom(symmetricKeyValue, InsecureSecretKeyAccess.get()))
                    .build()));
      }
    };
  }

  static EciesAeadHkdfDemHelper createHelper(Parameters parameters)
      throws GeneralSecurityException {
    if (parameters instanceof AesGcmParameters) {
      return createHelperAesGcm((AesGcmParameters) parameters);
    }
    if (parameters instanceof AesCtrHmacAeadParameters) {
      return createHelperAesCtrHmac((AesCtrHmacAeadParameters) parameters);
    }
    if (parameters instanceof AesSivParameters) {
      return createHelperAesSiv((AesSivParameters) parameters);
    }
    throw new GeneralSecurityException("Unsupported parameters for Ecies: " + parameters);
  }

  static final String toHmacAlgo(EciesParameters.HashType hash) throws GeneralSecurityException {
    if (hash.equals(EciesParameters.HashType.SHA1)) {
      return "HmacSha1";
    }
    if (hash.equals(EciesParameters.HashType.SHA224)) {
      return "HmacSha224";
    }
    if (hash.equals(EciesParameters.HashType.SHA256)) {
      return "HmacSha256";
    }
    if (hash.equals(EciesParameters.HashType.SHA384)) {
      return "HmacSha384";
    }
    if (hash.equals(EciesParameters.HashType.SHA512)) {
      return "HmacSha512";
    }
    throw new GeneralSecurityException("hash unsupported for EciesAeadHkdf: " + hash);
  }

  static final EnumTypeProtoConverter<EllipticCurves.CurveType, EciesParameters.CurveType>
      CURVE_TYPE_CONVERTER =
          EnumTypeProtoConverter.<EllipticCurves.CurveType, EciesParameters.CurveType>builder()
              .add(EllipticCurves.CurveType.NIST_P256, EciesParameters.CurveType.NIST_P256)
              .add(EllipticCurves.CurveType.NIST_P384, EciesParameters.CurveType.NIST_P384)
              .add(EllipticCurves.CurveType.NIST_P521, EciesParameters.CurveType.NIST_P521)
              .build();

  static final EnumTypeProtoConverter<EllipticCurves.PointFormatType, EciesParameters.PointFormat>
      POINT_FORMAT_TYPE_CONVERTER =
          EnumTypeProtoConverter
              .<EllipticCurves.PointFormatType, EciesParameters.PointFormat>builder()
              .add(PointFormatType.UNCOMPRESSED, EciesParameters.PointFormat.UNCOMPRESSED)
              .add(PointFormatType.COMPRESSED, EciesParameters.PointFormat.COMPRESSED)
              .add(
                  PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                  EciesParameters.PointFormat.LEGACY_UNCOMPRESSED)
              .build();

  public EciesAeadHkdfHybridEncrypt(
      final ECPublicKey recipientPublicKey,
      final byte[] hkdfSalt,
      String hkdfHmacAlgo,
      EllipticCurves.PointFormatType ecPointFormat,
      EciesAeadHkdfDemHelper demHelper)
      throws GeneralSecurityException {
    this(recipientPublicKey, hkdfSalt, hkdfHmacAlgo, ecPointFormat, demHelper, new byte[0]);
  }

  private EciesAeadHkdfHybridEncrypt(
      final ECPublicKey recipientPublicKey,
      final byte[] hkdfSalt,
      String hkdfHmacAlgo,
      EllipticCurves.PointFormatType ecPointFormat,
      EciesAeadHkdfDemHelper demHelper,
      byte[] outputPrefix)
      throws GeneralSecurityException {
    EllipticCurves.checkPublicKey(recipientPublicKey);
    this.senderKem = new EciesHkdfSenderKem(recipientPublicKey);
    this.hkdfSalt = hkdfSalt;
    this.hkdfHmacAlgo = hkdfHmacAlgo;
    this.ecPointFormat = ecPointFormat;
    this.demHelper = demHelper;
    this.outputPrefix = outputPrefix;
  }

  @AccessesPartialKey
  public static HybridEncrypt create(EciesPublicKey key) throws GeneralSecurityException {
    EllipticCurves.CurveType curveType =
        CURVE_TYPE_CONVERTER.toProtoEnum(key.getParameters().getCurveType());
    ECPublicKey recipientPublicKey =
        EllipticCurves.getEcPublicKey(
            curveType,
            key.getNistCurvePoint().getAffineX().toByteArray(),
            key.getNistCurvePoint().getAffineY().toByteArray());
    byte[] hkdfSalt = new byte[0];
    if (key.getParameters().getSalt() != null) {
      hkdfSalt = key.getParameters().getSalt().toByteArray();
    }
    return new EciesAeadHkdfHybridEncrypt(
        recipientPublicKey,
        hkdfSalt,
        toHmacAlgo(key.getParameters().getHashType()),
        POINT_FORMAT_TYPE_CONVERTER.toProtoEnum(key.getParameters().getNistCurvePointFormat()),
        createHelper(key.getParameters().getDemParameters()),
        key.getOutputPrefix().toByteArray());
  }

  public byte[] noPrefixEncrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    EciesHkdfSenderKem.KemKey kemKey =
        senderKem.generateKey(
            hkdfHmacAlgo,
            hkdfSalt,
            contextInfo,
            demHelper.getSymmetricKeySizeInBytes(),
            ecPointFormat);
    AeadOrDaead aead = demHelper.getAeadOrDaead(kemKey.getSymmetricKey());
    byte[] ciphertext = aead.encrypt(plaintext, EMPTY_AAD);
    byte[] header = kemKey.getKemBytes();
    return ByteBuffer.allocate(header.length + ciphertext.length)
        .put(header)
        .put(ciphertext)
        .array();
  }

  /**
   * Encrypts {@code plaintext} using {@code contextInfo} as <b>info</b>-parameter of the underlying
   * HKDF.
   *
   * @return resulting ciphertext.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    byte[] ciphertext = noPrefixEncrypt(plaintext, contextInfo);
    if (outputPrefix.length == 0) {
      return ciphertext;
    }
    return Bytes.concat(outputPrefix, ciphertext);
  }
}
