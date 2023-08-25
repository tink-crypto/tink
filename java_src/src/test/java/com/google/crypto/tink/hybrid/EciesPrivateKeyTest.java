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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class EciesPrivateKeyTest {
  private static final class NistCurveMapping {
    final EciesParameters.CurveType curveType;
    final EllipticCurves.CurveType ecNistCurve;

    NistCurveMapping(EciesParameters.CurveType curveType, EllipticCurves.CurveType ecNistCurve) {
      this.curveType = curveType;
      this.ecNistCurve = ecNistCurve;
    }
  }

  @DataPoints("nistCurvesMapping")
  public static final NistCurveMapping[] NIST_CURVES =
      new NistCurveMapping[] {
        new NistCurveMapping(
            EciesParameters.CurveType.NIST_P256, EllipticCurves.CurveType.NIST_P256),
        new NistCurveMapping(
            EciesParameters.CurveType.NIST_P384, EllipticCurves.CurveType.NIST_P384),
        new NistCurveMapping(
            EciesParameters.CurveType.NIST_P521, EllipticCurves.CurveType.NIST_P521)
      };

  @DataPoints("pointFormats")
  public static final EciesParameters.PointFormat[] POINT_FORMATS =
      new EciesParameters.PointFormat[] {
        EciesParameters.PointFormat.UNCOMPRESSED,
        EciesParameters.PointFormat.COMPRESSED,
        EciesParameters.PointFormat.LEGACY_UNCOMPRESSED,
      };

  @Test
  public void convertToAndFromJavaECPrivateKey() throws Exception {
    // Create an elliptic curve key pair using Java's KeyPairGenerator and get the public key.
    KeyPair keyPair = EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P256);
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

    // Before conversion, check that the spec of the ecPrivateKey are what we expect.
    assertThat(ecPrivateKey.getParams().getCurve())
        .isEqualTo(EllipticCurves.getCurveSpec(EllipticCurves.CurveType.NIST_P256).getCurve());
    assertThat(ecPublicKey.getParams().getCurve())
        .isEqualTo(EllipticCurves.getCurveSpec(EllipticCurves.CurveType.NIST_P256).getCurve());

    // Create EciesParameters that match the curve type.
    EciesParameters parameters =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    // Create EciesPublicKey and EciesPrivateKey using using ecPublicKey and ecPrivateKey.
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(
            parameters, ecPublicKey.getW(), /* idRequirement= */ null);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), InsecureSecretKeyAccess.get()));

    // Convert EciesPrivateKey back into a ECPrivateKey.
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    ECPrivateKey ecPrivateKey2 =
        (ECPrivateKey)
            keyFactory.generatePrivate(
                new ECPrivateKeySpec(
                    privateKey
                        .getNistPrivateKeyValue()
                        .getBigInteger(InsecureSecretKeyAccess.get()),
                    EllipticCurves.getCurveSpec(EllipticCurves.CurveType.NIST_P256)));
    assertThat(ecPrivateKey2.getS()).isEqualTo(ecPrivateKey.getS());
    assertThat(ecPrivateKey2.getParams().getCurve()).isEqualTo(ecPrivateKey.getParams().getCurve());
  }

  @Theory
  public void createNistCurvePrivateKey_hasCorrectParameters(
      @FromDataPoints("nistCurvesMapping") NistCurveMapping nistCurveMapping,
      @FromDataPoints("pointFormats") EciesParameters.PointFormat pointFormat)
      throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(nistCurveMapping.curveType)
            .setNistCurvePointFormat(pointFormat)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(
                XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX))
            .build();

    KeyPair keyPair = EllipticCurves.generateKeyPair(nistCurveMapping.ecNistCurve);
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(params, ecPublicKey.getW(), /* idRequirement= */ null);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), InsecureSecretKeyAccess.get()));

    assertThat(privateKey.getParameters()).isEqualTo(params);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getX25519PrivateKeyBytes()).isEqualTo(null);
    assertThat(privateKey.getNistPrivateKeyValue().getBigInteger(InsecureSecretKeyAccess.get()))
        .isEqualTo(ecPrivateKey.getS());
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void createX25519PrivateKey_hasCorrectParameters() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);

    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ null);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForCurveX25519(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(privateKey.getParameters()).isEqualTo(params);
    assertThat(privateKey.getPublicKey()).isEqualTo(publicKey);
    assertThat(privateKey.getX25519PrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()))
        .isEqualTo(privateKeyBytes);
    assertThat(privateKey.getNistPrivateKeyValue()).isNull();
    assertThat(privateKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(privateKey.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void callCreateForNistCurveWithX25519PublicKey_throws() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));
    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(params, publicKeyBytes, /* idRequirement= */ null);

    ECPrivateKey ecPrivateKey =
        (ECPrivateKey)
            EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P256).getPrivate();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesPrivateKey.createForNistCurve(
                publicKey,
                SecretBigInteger.fromBigInteger(
                    ecPrivateKey.getS(), InsecureSecretKeyAccess.get())));
  }

  @Test
  public void callCreateForCurve25519WithNistPublicKey_throws() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    ECPublicKey ecPublicKey =
        (ECPublicKey)
            EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P256).getPublic();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(params, ecPublicKey.getW(), /* idRequirement= */ null);

    byte[] privateKeyBytes = X25519.generatePrivateKey();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesPrivateKey.createForCurveX25519(
                publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get())));
  }

  @Theory
  public void createNistCurvePrivateKey_failsWithMismatchedPublicKey() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();
    ECPublicKey ecPublicKey =
        (ECPublicKey)
            EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P256).getPublic();
    ECPrivateKey ecPrivateKey =
        (ECPrivateKey)
            EllipticCurves.generateKeyPair(EllipticCurves.CurveType.NIST_P256).getPrivate();

    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(params, ecPublicKey.getW(), /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesPrivateKey.createForNistCurve(
                publicKey,
                SecretBigInteger.fromBigInteger(
                    ecPrivateKey.getS(), InsecureSecretKeyAccess.get())));
  }

  @Test
  public void createX25519PrivateKey_withTooShortKey_fails() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ null);
    byte[] tooShort = Arrays.copyOf(privateKeyBytes, privateKeyBytes.length - 1);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesPrivateKey.createForCurveX25519(
                publicKey, SecretBytes.copyFrom(tooShort, InsecureSecretKeyAccess.get())));
  }

  @Test
  public void createX25519PrivateKey_withTooLongKey_fails() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ null);
    byte[] tooLong = Arrays.copyOf(privateKeyBytes, privateKeyBytes.length + 1);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesPrivateKey.createForCurveX25519(
                publicKey, SecretBytes.copyFrom(tooLong, InsecureSecretKeyAccess.get())));
  }

  @Test
  public void createX25519PrivateKey_failsWithMismatchedPublicKey() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    byte[] privateKeyBytes = X25519.generatePrivateKey();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));
    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(params, publicKeyBytes, /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            EciesPrivateKey.createForCurveX25519(
                publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get())));
  }

  @Test
  public void sameX25519Keys_areEqual() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ null);

    EciesPrivateKey privateKey1 =
        EciesPrivateKey.createForCurveX25519(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));
    EciesPrivateKey privateKey2 =
        EciesPrivateKey.createForCurveX25519(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(privateKey1.equalsKey(privateKey2)).isTrue();
  }

  @Theory
  public void sameNistKeys_areEqual(
      @FromDataPoints("nistCurvesMapping") NistCurveMapping nistCurveMapping,
      @FromDataPoints("pointFormats") EciesParameters.PointFormat pointFormat)
      throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(nistCurveMapping.curveType)
            .setNistCurvePointFormat(pointFormat)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();
    KeyPair keyPair = EllipticCurves.generateKeyPair(nistCurveMapping.ecNistCurve);
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(params, ecPublicKey.getW(), /* idRequirement= */ null);

    EciesPrivateKey privateKey1 =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), InsecureSecretKeyAccess.get()));
    EciesPrivateKey privateKey2 =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), InsecureSecretKeyAccess.get()));

    assertThat(privateKey1.equalsKey(privateKey2)).isTrue();
  }

  @Test
  public void testDifferentPublicKeyParams_areNotEqual() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.TINK)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);
    EciesPublicKey publicKey1 =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ 123);
    EciesPublicKey publicKey2 =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ 456);

    EciesPrivateKey privateKey1 =
        EciesPrivateKey.createForCurveX25519(
            publicKey1, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));
    EciesPrivateKey privateKey2 =
        EciesPrivateKey.createForCurveX25519(
            publicKey2, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(privateKey1.equalsKey(privateKey2)).isFalse();
  }

  @Test
  public void differentKeyTypesAreNotEqual() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);

    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ null);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForCurveX25519(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(publicKey.equalsKey(privateKey)).isFalse();
  }
}
