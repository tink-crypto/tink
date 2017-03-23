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
import java.security.spec.EllipticCurve;
import java.util.Arrays;

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

  // TODO(bleichen): Some of the methods below were written so that AdSpam could use them
  //   independently. Check if some of them are unnecessary or don't need to be public.

  public static int encodingSizeInBytes(EllipticCurve curve, EcPointFormat format)
      throws GeneralSecurityException {
    int coordinateSize = EcUtil.fieldSizeInBytes(curve);
    switch (format) {
      case UNCOMPRESSED:
        return 2 * coordinateSize + 1;
      case COMPRESSED:
        return coordinateSize + 1;
      default:
        throw new GeneralSecurityException("unknown EC point format");
    }
  }

  /**
   * Decodes an encoded point on an elliptic curve. This method checks that the
   * encoded point is on the curve.
   * @param curve the elliptic curve
   * @param format the format used to enocde the point
   * @param encoded the encoded point
   * @return the point
   * @throws GeneralSecurityException if the encoded point
   * is invalid or if the curve or format are not supported.
   */
  public static ECPoint ecPointDecode(
      EllipticCurve curve, EcPointFormat format, byte[] encoded)
      throws GeneralSecurityException {
    int coordinateSize = EcUtil.fieldSizeInBytes(curve);
    switch (format) {
      case UNCOMPRESSED:
        {
          if (encoded.length != 2 * coordinateSize + 1) {
            throw new GeneralSecurityException("invalid point size");
          }
          if (encoded[0] != 4) {
            throw new GeneralSecurityException("invalid point format");
          }
          BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, coordinateSize + 1));
          BigInteger y =
              new BigInteger(1, Arrays.copyOfRange(encoded, coordinateSize + 1, encoded.length));
          ECPoint point = new ECPoint(x, y);
          EcUtil.checkPointOnCurve(point, curve);
          return point;
        }
      case COMPRESSED:
        {
          BigInteger p = EcUtil.getModulus(curve);
          if (encoded.length != coordinateSize + 1) {
            throw new GeneralSecurityException("compressed point has wrong length");
          }
          boolean lsb;
          if (encoded[0] == 2) {
            lsb = false;
          } else if (encoded[0] == 3) {
            lsb = true;
          } else {
            throw new GeneralSecurityException("invalid format");
          }
          BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
          if (x.signum() == -1 || x.compareTo(p) != -1) {
            throw new GeneralSecurityException("x is out of range");
          }
          BigInteger y = EcUtil.getY(x, lsb, curve);
          return new ECPoint(x, y);
        }
      default:
        throw new GeneralSecurityException("invalid format:" + format);
    }
  }

  /**
   * Encodes a point on an elliptic curve.
   *
   * @param curve the elliptic curve
   * @param format the format for the encoding
   * @param point the point to encode
   * @return the encoded key exchange
   * @throws GeneralSecurityException if the point is not on the curve or
   *     if the format is not supported.
   */
  public static byte[] ecPointEncode(EllipticCurve curve, EcPointFormat format, ECPoint point)
      throws GeneralSecurityException {
    EcUtil.checkPointOnCurve(point, curve);
    int coordinateSize = EcUtil.fieldSizeInBytes(curve);
    switch (format) {
      case UNCOMPRESSED:
        {
          byte[] encoded = new byte[2 * coordinateSize + 1];
          byte[] x = point.getAffineX().toByteArray();
          byte[] y = point.getAffineY().toByteArray();
          // Order of System.arraycopy is important because x,y can have leading 0's.
          System.arraycopy(y, 0, encoded, 1 + 2 * coordinateSize - y.length, y.length);
          System.arraycopy(x, 0, encoded, 1 + coordinateSize - x.length, x.length);
          encoded[0] = 4;
          return encoded;
        }
      case COMPRESSED:
        {
          byte[] encoded = new byte[coordinateSize + 1];
          byte[] x = point.getAffineX().toByteArray();
          System.arraycopy(x, 0, encoded, 1 + coordinateSize - x.length, x.length);
          encoded[0] = (byte) (point.getAffineY().testBit(0) ? 3 : 2);
          return encoded;
        }
      default:
        throw new GeneralSecurityException("invalid format:" + format);
    }
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

    Keyset.Key first = keyset.getKey(0);
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
}
