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

import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class HpkePublicKeyTest {
  private static final class NistKemTuple {
    final HpkeParameters.KemId kemId;
    final EllipticCurves.CurveType curve;

    NistKemTuple(HpkeParameters.KemId kemId, EllipticCurves.CurveType curve) {
      this.kemId = kemId;
      this.curve = curve;
    }
  }

  @DataPoints("nistKemTuples")
  public static final NistKemTuple[] KEMS =
      new NistKemTuple[] {
        new NistKemTuple(
            HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256, EllipticCurves.CurveType.NIST_P256),
        new NistKemTuple(
            HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384, EllipticCurves.CurveType.NIST_P384),
        new NistKemTuple(
            HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512, EllipticCurves.CurveType.NIST_P521),
      };

  @Theory
  public void createNistCurvePublicKey(@FromDataPoints("nistKemTuples") NistKemTuple tuple)
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(tuple.kemId)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    ECPublicKey ecPublicKey = (ECPublicKey) EllipticCurves.generateKeyPair(tuple.curve).getPublic();
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            EllipticCurves.pointEncode(
                tuple.curve, PointFormatType.UNCOMPRESSED, ecPublicKey.getW()));

    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    assertThat(publicKey.getPublicKeyBytes()).isEqualTo(publicKeyBytes);
    assertThat(publicKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(publicKey.getParameters()).isEqualTo(params);
    assertThat(publicKey.getIdRequirementOrNull()).isEqualTo(null);
  }

  @Test
  public void createX25519PublicKey() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));

    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    assertThat(publicKey.getPublicKeyBytes()).isEqualTo(publicKeyBytes);
    assertThat(publicKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(publicKey.getParameters()).isEqualTo(params);
    assertThat(publicKey.getIdRequirementOrNull()).isEqualTo(null);
  }

  @Theory
  public void createNistCurvePublicKey_failsWithWrongKeyLength(
      @FromDataPoints("nistKemTuples") NistKemTuple tuple) throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(tuple.kemId)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    ECPublicKey ecPublicKey = (ECPublicKey) EllipticCurves.generateKeyPair(tuple.curve).getPublic();
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            EllipticCurves.pointEncode(
                tuple.curve, PointFormatType.UNCOMPRESSED, ecPublicKey.getW()));
    Bytes tooShort = Bytes.copyFrom(publicKeyBytes.toByteArray(), 0, publicKeyBytes.size() - 1);
    byte[] tooLongBytes = new byte[publicKeyBytes.size() + 1];
    System.arraycopy(publicKeyBytes.toByteArray(), 0, tooLongBytes, 0, publicKeyBytes.size());
    Bytes tooLong = Bytes.copyFrom(tooLongBytes);

    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(params, tooShort, /* idRequirement= */ null));

    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(params, tooLong, /* idRequirement= */ null));
  }

  @Test
  public void createX25519PublicKey_failsWithWrongKeyLength() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));
    Bytes tooShort = Bytes.copyFrom(publicKeyBytes.toByteArray(), 0, publicKeyBytes.size() - 1);
    byte[] tooLongBytes = new byte[publicKeyBytes.size() + 1];
    System.arraycopy(publicKeyBytes.toByteArray(), 0, tooLongBytes, 0, publicKeyBytes.size());
    Bytes tooLong = Bytes.copyFrom(tooLongBytes);

    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(params, tooShort, /* idRequirement= */ null));

    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(params, tooLong, /* idRequirement= */ null));
  }

  /** Copied from {@link EllipticCurves#pointEncode} to bypass point validation. */
  private static byte[] encodeUncompressedPoint(EllipticCurve curve, ECPoint point)
      throws GeneralSecurityException {
    int coordinateSize = EllipticCurves.fieldSizeInBytes(curve);
    byte[] encoded = new byte[2 * coordinateSize + 1];
    byte[] x = BigIntegerEncoding.toBigEndianBytes(point.getAffineX());
    byte[] y = BigIntegerEncoding.toBigEndianBytes(point.getAffineY());
    // Order of System.arraycopy is important because x,y can have leading 0's.
    System.arraycopy(y, 0, encoded, 1 + 2 * coordinateSize - y.length, y.length);
    System.arraycopy(x, 0, encoded, 1 + coordinateSize - x.length, x.length);
    encoded[0] = 4;
    return encoded;
  }

  @Theory
  public void createNistCurvePublicKey_failsIfPointNotOnCurve(
      @FromDataPoints("nistKemTuples") NistKemTuple tuple) throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(tuple.kemId)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    ECPublicKey ecPublicKey = (ECPublicKey) EllipticCurves.generateKeyPair(tuple.curve).getPublic();
    ECPoint point = ecPublicKey.getW();
    ECPoint badPoint = new ECPoint(point.getAffineX(), point.getAffineY().subtract(BigInteger.ONE));

    Bytes publicKeyBytes =
        Bytes.copyFrom(
            encodeUncompressedPoint(EllipticCurves.getCurveSpec(tuple.curve).getCurve(), badPoint));

    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null));
  }

  @Test
  public void createPublicKey_failsWithMismatchedIdRequirement() throws Exception {
    HpkeParameters.Builder paramsBuilder =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM);
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));

    HpkeParameters noPrefixParams =
        paramsBuilder.setVariant(HpkeParameters.Variant.NO_PREFIX).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(noPrefixParams, publicKeyBytes, /* idRequirement= */ 123));

    HpkeParameters tinkParams = paramsBuilder.setVariant(HpkeParameters.Variant.TINK).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(tinkParams, publicKeyBytes, /* idRequirement= */ null));

    HpkeParameters crunchyParams = paramsBuilder.setVariant(HpkeParameters.Variant.CRUNCHY).build();
    assertThrows(
        GeneralSecurityException.class,
        () -> HpkePublicKey.create(crunchyParams, publicKeyBytes, /* idRequirement= */ null));
  }

  @Test
  public void getOutputPrefix() throws Exception {
    HpkeParameters.Builder paramsBuilder =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM);
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));

    HpkeParameters noPrefixParams =
        paramsBuilder.setVariant(HpkeParameters.Variant.NO_PREFIX).build();
    HpkePublicKey noPrefixPublicKey =
        HpkePublicKey.create(noPrefixParams, publicKeyBytes, /* idRequirement= */ null);
    assertThat(noPrefixPublicKey.getIdRequirementOrNull()).isEqualTo(null);
    assertThat(noPrefixPublicKey.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));

    HpkeParameters tinkParams = paramsBuilder.setVariant(HpkeParameters.Variant.TINK).build();
    HpkePublicKey tinkPublicKey =
        HpkePublicKey.create(tinkParams, publicKeyBytes, /* idRequirement= */ 0x02030405);
    assertThat(tinkPublicKey.getIdRequirementOrNull()).isEqualTo(0x02030405);
    assertThat(tinkPublicKey.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}));

    HpkeParameters crunchyParams = paramsBuilder.setVariant(HpkeParameters.Variant.CRUNCHY).build();
    HpkePublicKey crunchyPublicKey =
        HpkePublicKey.create(crunchyParams, publicKeyBytes, /* idRequirement= */ 0x01020304);
    assertThat(crunchyPublicKey.getIdRequirementOrNull()).isEqualTo(0x01020304);
    assertThat(crunchyPublicKey.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x01, 0x02, 0x03, 0x04}));
  }

  @Test
  public void sameKeysAreEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));

    HpkePublicKey publicKey1 =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);
    HpkePublicKey publicKey2 =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    assertThat(publicKey1.equalsKey(publicKey2)).isTrue();
  }

  @Test
  public void differentParamsAreNotEqual() throws Exception {
    HpkeParameters.Builder paramsBuilder =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM);
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));

    HpkeParameters params1 = paramsBuilder.setVariant(HpkeParameters.Variant.TINK).build();
    HpkePublicKey publicKey1 =
        HpkePublicKey.create(params1, publicKeyBytes, /* idRequirement= */ 123);
    HpkeParameters params2 = paramsBuilder.setVariant(HpkeParameters.Variant.CRUNCHY).build();
    HpkePublicKey publicKey2 =
        HpkePublicKey.create(params2, publicKeyBytes, /* idRequirement= */ 123);

    assertThat(publicKey1.equalsKey(publicKey2)).isFalse();
  }

  @Test
  public void differentKeyBytesAreNotEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    Bytes publicKeyBytes1 = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));
    byte[] buf2 = publicKeyBytes1.toByteArray();
    buf2[0] = (byte) (buf2[0] ^ 0x01);
    Bytes publicKeyBytes2 = Bytes.copyFrom(buf2);

    HpkePublicKey publicKey1 =
        HpkePublicKey.create(params, publicKeyBytes1, /* idRequirement= */ null);
    HpkePublicKey publicKey2 =
        HpkePublicKey.create(params, publicKeyBytes2, /* idRequirement= */ null);

    assertThat(publicKey1.equalsKey(publicKey2)).isFalse();
  }

  @Test
  public void differentIdsAreNotEqual() throws Exception {
    HpkeParameters.Builder paramsBuilder =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM);
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));

    HpkeParameters params1 = paramsBuilder.setVariant(HpkeParameters.Variant.TINK).build();
    HpkePublicKey publicKey1 =
        HpkePublicKey.create(params1, publicKeyBytes, /* idRequirement= */ 123);
    HpkeParameters params2 = paramsBuilder.setVariant(HpkeParameters.Variant.TINK).build();
    HpkePublicKey publicKey2 =
        HpkePublicKey.create(params2, publicKeyBytes, /* idRequirement= */ 456);

    assertThat(publicKey1.equalsKey(publicKey2)).isFalse();
  }
}
