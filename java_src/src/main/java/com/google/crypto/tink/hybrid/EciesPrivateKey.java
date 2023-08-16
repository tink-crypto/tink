// Copyright 2023 Google LLC
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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import javax.annotation.Nullable;

/** Representation of the decryption function for an ECIES hybrid encryption primitive. */
@Immutable
public final class EciesPrivateKey extends HybridPrivateKey {
  private final EciesPublicKey publicKey;

  /** Exactly one of nistPrivateKeyValue and x25519PrivateKeyBytes is non-null. */
  @Nullable private final SecretBigInteger nistPrivateKeyValue;

  @Nullable private final SecretBytes x25519PrivateKeyBytes;

  private EciesPrivateKey(
      EciesPublicKey publicKey,
      @Nullable SecretBigInteger nistPrivateKeyValue,
      @Nullable SecretBytes x25519PrivateKeyBytes) {
    this.publicKey = publicKey;
    this.nistPrivateKeyValue = nistPrivateKeyValue;
    this.x25519PrivateKeyBytes = x25519PrivateKeyBytes;
  }

  private static ECParameterSpec toParameterSpecNistCurve(EciesParameters.CurveType curveType) {
    if (curveType == EciesParameters.CurveType.NIST_P256) {
      return EllipticCurves.getNistP256Params();
    }
    if (curveType == EciesParameters.CurveType.NIST_P384) {
      return EllipticCurves.getNistP384Params();
    }
    if (curveType == EciesParameters.CurveType.NIST_P521) {
      return EllipticCurves.getNistP521Params();
    }
    throw new IllegalArgumentException("Unable to determine NIST curve type for " + curveType);
  }

  private static void validateNistPrivateKeyValue(
      BigInteger privateValue, ECPoint publicPoint, EciesParameters.CurveType curveType)
      throws GeneralSecurityException {
    BigInteger order = toParameterSpecNistCurve(curveType).getOrder();
    if ((privateValue.signum() <= 0) || (privateValue.compareTo(order) >= 0)) {
      throw new GeneralSecurityException("Invalid private value");
    }
    ECPoint p =
        EllipticCurvesUtil.multiplyByGenerator(privateValue, toParameterSpecNistCurve(curveType));
    if (!p.equals(publicPoint)) {
      throw new GeneralSecurityException("Invalid private value");
    }
  }

  private static void validateX25519PrivateKeyBytes(byte[] privateKeyBytes, byte[] publicKeyBytes)
      throws GeneralSecurityException {
    if (privateKeyBytes.length != 32) {
      throw new GeneralSecurityException("Private key bytes length for X25519 curve must be 32");
    }
    byte[] expectedPublicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
    if (!Arrays.equals(expectedPublicKeyBytes, publicKeyBytes)) {
      throw new GeneralSecurityException("Invalid private key for public key.");
    }
  }

  /**
   * Creates a new ECIES private key using Curve25519.
   *
   * @param publicKey Corresponding ECIES public key for this private key
   * @param x25519PrivateKeyBytes private key bytes
   */
  @AccessesPartialKey
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static EciesPrivateKey createForCurveX25519(
      EciesPublicKey publicKey, SecretBytes x25519PrivateKeyBytes) throws GeneralSecurityException {
    if (publicKey == null) {
      throw new GeneralSecurityException(
          "ECIES private key cannot be constructed without an ECIES public key");
    }
    if (publicKey.getX25519CurvePointBytes() == null) {
      throw new GeneralSecurityException(
          "ECIES private key for X25519 curve cannot be constructed with NIST-curve public key");
    }
    if (x25519PrivateKeyBytes == null) {
      throw new GeneralSecurityException("ECIES private key cannot be constructed without secret");
    }
    validateX25519PrivateKeyBytes(
        x25519PrivateKeyBytes.toByteArray(InsecureSecretKeyAccess.get()),
        publicKey.getX25519CurvePointBytes().toByteArray());

    return new EciesPrivateKey(publicKey, null, x25519PrivateKeyBytes);
  }

  /**
   * Creates a new ECIES private key using NIST Curves.
   *
   * @param publicKey Corresponding ECIES public key for this private key
   * @param nistPrivateKeyValue private big integer value in bigendian representation
   */
  @AccessesPartialKey
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static EciesPrivateKey createForNistCurve(
      EciesPublicKey publicKey, SecretBigInteger nistPrivateKeyValue)
      throws GeneralSecurityException {
    if (publicKey == null) {
      throw new GeneralSecurityException(
          "ECIES private key cannot be constructed without an ECIES public key");
    }
    if (publicKey.getNistCurvePoint() == null) {
      throw new GeneralSecurityException(
          "ECIES private key for NIST curve cannot be constructed with X25519-curve public key");
    }
    if (nistPrivateKeyValue == null) {
      throw new GeneralSecurityException("ECIES private key cannot be constructed without secret");
    }
    validateNistPrivateKeyValue(
        nistPrivateKeyValue.getBigInteger(InsecureSecretKeyAccess.get()),
        publicKey.getNistCurvePoint(),
        publicKey.getParameters().getCurveType());

    return new EciesPrivateKey(publicKey, nistPrivateKeyValue, null);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @Nullable
  public SecretBytes getX25519PrivateKeyBytes() {
    return x25519PrivateKeyBytes;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @Nullable
  public SecretBigInteger getNistPrivateKeyValue() {
    return nistPrivateKeyValue;
  }

  @Override
  public EciesParameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public EciesPublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof EciesPrivateKey)) {
      return false;
    }
    EciesPrivateKey other = (EciesPrivateKey) o;
    if (!publicKey.equalsKey(other.publicKey)) {
      return false;
    }
    if (x25519PrivateKeyBytes == null && other.x25519PrivateKeyBytes == null) {
      return nistPrivateKeyValue.equalsSecretBigInteger(other.nistPrivateKeyValue);
    }

    return x25519PrivateKeyBytes.equalsSecretBytes(other.x25519PrivateKeyBytes);
  }
}
