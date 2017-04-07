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

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.EcUtil;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

/**
 * Various helpers.
 */
public class Util {
  /**
   * @return a KeysetInfo-proto from a {@code keyset} protobuf.
   */
  public static KeysetInfo getKeysetInfo(Keyset keyset) {
    KeysetInfo.Builder info = KeysetInfo.newBuilder()
        .setPrimaryKeyId(keyset.getPrimaryKeyId());
    for (Keyset.Key key : keyset.getKeyList()) {
      info.addKeyInfo(getKeyInfo(key));
    }
    return info.build();
  }

  /**
   * @return a KeyInfo-proto from a {@code key} protobuf.
   */
  public static KeysetInfo.KeyInfo getKeyInfo(Keyset.Key key) {
    return KeysetInfo.KeyInfo.newBuilder()
        .setTypeUrl(key.getKeyData().getTypeUrl())
        .setStatus(key.getStatus())
        .setOutputPrefixType(key.getOutputPrefixType())
        .setKeyId(key.getKeyId())
        .setGeneratedAt(key.getGeneratedAt())
        .setValidUntil(key.getValidUntil())
        .build();
  }



  /**
   * Returns the ECParameterSpec for a named curve.
   *
   * @param curve the curve type
   * @return the ECParameterSpec for the curve.
   */
  public static ECParameterSpec getCurveSpec(EllipticCurveType curve)
      throws NoSuchAlgorithmException {
    switch(curve) {
      case NIST_P256:
        return EcUtil.getNistP256Params();
      case NIST_P384:
        return EcUtil.getNistP384Params();
      case NIST_P521:
        return EcUtil.getNistP521Params();
      default:
        throw new NoSuchAlgorithmException("curve not implemented:" + curve);
    }
  }

  /**
   * Returns an {@code ECPublicKey} from {@code curve} type and {@code x} and {@code y}
   * coordinates.
   */
  public static ECPublicKey getEcPublicKey(EllipticCurveType curve,
      final byte[] x, final byte[] y) throws GeneralSecurityException {
    ECParameterSpec ecParams = getCurveSpec(curve);
    BigInteger pubX = new BigInteger(1, x);
    BigInteger pubY = new BigInteger(1, y);
    ECPoint w = new ECPoint(pubX, pubY);
    EcUtil.checkPointOnCurve(w, ecParams.getCurve());
    ECPublicKeySpec spec = new ECPublicKeySpec(w, ecParams);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return (ECPublicKey) kf.generatePublic(spec);
  }

  /**
   * Returns an {@code ECPrivateKey} from {@code curve} type and {@code keyValue}.
   */
  public static ECPrivateKey getEcPrivateKey(EllipticCurveType curve,
      final byte[] keyValue) throws GeneralSecurityException {
    ECParameterSpec ecParams = getCurveSpec(curve);
    BigInteger privValue = new BigInteger(1, keyValue);
    ECPrivateKeySpec spec = new ECPrivateKeySpec(privValue, ecParams);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return (ECPrivateKey) kf.generatePrivate(spec);
  }

  /**
   * Returns the HMAC algorithm name corresponding to a hash type.
   *
   * @param hash the hash type
   * @return the JCE's HMAC algorithm name for the hash.
   */
  public static String hashToHmacAlgorithmName(HashType hash) throws NoSuchAlgorithmException {
    switch(hash) {
      case SHA1:
        return "HmacSha1";
      case SHA256:
        return "HmacSha256";
      case SHA512:
        return "HmacSha512";
      default:
        throw new NoSuchAlgorithmException("hash unsupported for HMAC: " + hash);
    }
  }

  /**
   * Generates a new key pair for {@code curve}.
   */
  public static KeyPair generateKeyPair(EllipticCurveType curve) throws GeneralSecurityException {
    ECParameterSpec ecParams = getCurveSpec(curve);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(ecParams);
    return keyGen.generateKeyPair();
  }

  /**
   * Validates a {@code key}.
   * @throws GeneralSecurityException if {@code key} is invalid.
   */
  public static void validateKey(Keyset.Key key) throws GeneralSecurityException {
    if (!key.hasKeyData()) {
      throw new GeneralSecurityException(
          String.format("key %d has no key data", key.getKeyId()));
    }

    if (key.getOutputPrefixType() == OutputPrefixType.UNKNOWN_PREFIX) {
      throw new GeneralSecurityException(
          String.format("key %d has unknown prefix", key.getKeyId()));
    }

    if (key.getStatus() == KeyStatusType.UNKNOWN_STATUS) {
      throw new GeneralSecurityException(
          String.format("key %d has unknown status", key.getKeyId()));
    }

    if (key.getKeyId() <= 0) {
      throw new GeneralSecurityException(
          String.format("key has a non-positive key id: %d", key.getKeyId()));
    }
  }

  /**
   * Validates a {@code Keyset}.
   * @throws GeneralSecurityException if {@code keyset} is invalid.
   */
  public static void validateKeyset(Keyset keyset) throws GeneralSecurityException {
    if (keyset.getKeyCount() == 0) {
      throw new GeneralSecurityException("empty keyset");
    }

    int primaryKeyId = keyset.getPrimaryKeyId();
    boolean hasPrimaryKey = false;
    for (Keyset.Key key : keyset.getKeyList()) {
      validateKey(key);
      if (key.getStatus() == KeyStatusType.ENABLED && key.getKeyId() == primaryKeyId) {
        if (hasPrimaryKey) {
          throw new GeneralSecurityException("keyset contains multiple primary keys");
        }
        hasPrimaryKey = true;
      }
      // TODO(thaidn): use TypeLiteral to ensure that all keys are of the same primitive.
    }
    if (!hasPrimaryKey) {
      throw new GeneralSecurityException("keyset doesn't contain a valid primary key");
    }
  }

  /**
   * Converts com.google.cloud.crypto.tink.CommonProto.EcPointFormat
   * into com.google.cloud.crypto.tink.subtle.PointFormat.
   * The duplication of the enum for the point compression format is necessary because subtle is
   * independent of protocol buffers.
   */
  public static EcUtil.PointFormat getPointFormat(EcPointFormat format)
      throws GeneralSecurityException {
    switch(format) {
      case COMPRESSED:
        return EcUtil.PointFormat.COMPRESSED;
      case UNCOMPRESSED:
        return EcUtil.PointFormat.UNCOMPRESSED;
      default:
        // Should not happen.
        throw new GeneralSecurityException("Unsupported point format:" + format);
    }
  }
}
