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
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.EllipticCurves.PointFormatType;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class HpkePrivateKeyTest {
  private static final class NistKemTuple {
    final HpkeParameters.KemId kemId;
    final EllipticCurves.CurveType curve;
    final int privateKeyLength;

    NistKemTuple(HpkeParameters.KemId kemId, EllipticCurves.CurveType curve, int privateKeyLength) {
      this.kemId = kemId;
      this.curve = curve;
      this.privateKeyLength = privateKeyLength;
    }
  }

  @DataPoints("nistKemTuples")
  public static final NistKemTuple[] KEMS =
      new NistKemTuple[] {
        new NistKemTuple(
            HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256, EllipticCurves.CurveType.NIST_P256, 32),
        new NistKemTuple(
            HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384, EllipticCurves.CurveType.NIST_P384, 48),
        new NistKemTuple(
            HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512, EllipticCurves.CurveType.NIST_P521, 66),
      };

  @Theory
  public void createNistCurvePrivateKey(@FromDataPoints("nistKemTuples") NistKemTuple tuple)
      throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(tuple.kemId)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    KeyPair keyPair = EllipticCurves.generateKeyPair(tuple.curve);
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            EllipticCurves.pointEncode(
                tuple.curve, PointFormatType.UNCOMPRESSED, ecPublicKey.getW()));
    byte[] privateKeyBytes =
        BigIntegerEncoding.toBigEndianBytesOfFixedLength(
            ecPrivateKey.getS(), tuple.privateKeyLength);
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(privateKey.getParameters()).isEqualTo(params);
    assertThat(privateKey.getPublicKey().equalsKey(publicKey)).isTrue();
    assertThat(privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()))
        .isEqualTo(privateKeyBytes);
  }

  @Test
  public void createX25519PrivateKey() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(privateKeyBytes));
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(privateKey.getParameters()).isEqualTo(params);
    assertThat(privateKey.getPublicKey().equalsKey(publicKey)).isTrue();
    assertThat(privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()))
        .isEqualTo(privateKeyBytes);
  }

  @Theory
  public void createNistCurvePrivateKey_failsWithWrongKeyLength(
      @FromDataPoints("nistKemTuples") NistKemTuple tuple) throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(tuple.kemId)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    KeyPair keyPair = EllipticCurves.generateKeyPair(tuple.curve);
    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            EllipticCurves.pointEncode(
                tuple.curve, PointFormatType.UNCOMPRESSED, ecPublicKey.getW()));
    byte[] privateKeyBytes =
        BigIntegerEncoding.toBigEndianBytesOfFixedLength(
            ecPrivateKey.getS(), tuple.privateKeyLength);
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    byte[] tooShortBytes = Arrays.copyOf(privateKeyBytes, privateKeyBytes.length - 1);
    SecretBytes tooShort = SecretBytes.copyFrom(tooShortBytes, InsecureSecretKeyAccess.get());
    byte[] tooLongBytes = Arrays.copyOf(privateKeyBytes, privateKeyBytes.length + 1);
    SecretBytes tooLong = SecretBytes.copyFrom(tooLongBytes, InsecureSecretKeyAccess.get());

    assertThrows(GeneralSecurityException.class, () -> HpkePrivateKey.create(publicKey, tooShort));
    assertThrows(GeneralSecurityException.class, () -> HpkePrivateKey.create(publicKey, tooLong));
  }

  @Theory
  public void createNistCurvePrivateKey_failsWithMismatchedPublicKey(
      @FromDataPoints("nistKemTuples") NistKemTuple tuple) throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(tuple.kemId)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    ECPublicKey ecPublicKey = (ECPublicKey) EllipticCurves.generateKeyPair(tuple.curve).getPublic();
    ECPrivateKey ecPrivateKey =
        (ECPrivateKey) EllipticCurves.generateKeyPair(tuple.curve).getPrivate();
    Bytes publicKeyBytes =
        Bytes.copyFrom(
            EllipticCurves.pointEncode(
                tuple.curve, PointFormatType.UNCOMPRESSED, ecPublicKey.getW()));
    byte[] privateKeyBytes =
        BigIntegerEncoding.toBigEndianBytesOfFixedLength(
            ecPrivateKey.getS(), tuple.privateKeyLength);
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            HpkePrivateKey.create(
                publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get())));
  }

  @Test
  public void createX25519PrivateKey_failsWithWrongKeyLength() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(privateKeyBytes));
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    byte[] tooShortBytes = Arrays.copyOf(privateKeyBytes, privateKeyBytes.length - 1);
    SecretBytes tooShort = SecretBytes.copyFrom(tooShortBytes, InsecureSecretKeyAccess.get());
    byte[] tooLongBytes = Arrays.copyOf(privateKeyBytes, privateKeyBytes.length + 1);
    SecretBytes tooLong = SecretBytes.copyFrom(tooLongBytes, InsecureSecretKeyAccess.get());

    assertThrows(GeneralSecurityException.class, () -> HpkePrivateKey.create(publicKey, tooShort));
    assertThrows(GeneralSecurityException.class, () -> HpkePrivateKey.create(publicKey, tooLong));
  }

  @Test
  public void createX25519PrivateKey_failsWithMismatchedPublicKey() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(X25519.generatePrivateKey()));
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    assertThrows(
        GeneralSecurityException.class,
        () ->
            HpkePrivateKey.create(
                publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get())));
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
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(privateKeyBytes));
    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ null);

    HpkePrivateKey privateKey1 =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));
    HpkePrivateKey privateKey2 =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(privateKey1.equalsKey(privateKey2)).isTrue();
  }

  @Test
  public void differentPublicKeyParamsAreNotEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(privateKeyBytes));
    HpkePublicKey publicKey1 =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ 123);
    HpkePublicKey publicKey2 =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ 456);

    HpkePrivateKey privateKey1 =
        HpkePrivateKey.create(
            publicKey1, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));
    HpkePrivateKey privateKey2 =
        HpkePrivateKey.create(
            publicKey2, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(privateKey1.getParameters()).isEqualTo(privateKey2.getParameters());
    assertThat(privateKey1.getPrivateKeyBytes().equalsSecretBytes(privateKey2.getPrivateKeyBytes()))
        .isTrue();
    assertThat(privateKey1.getPublicKey()).isNotEqualTo(privateKey2.getPublicKey());
    assertThat(privateKey1.equalsKey(privateKey2)).isFalse();
  }

  @Test
  public void differentKeyTypesAreNotEqual() throws Exception {
    HpkeParameters params =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    byte[] privateKeyBytes = X25519.generatePrivateKey();
    Bytes publicKeyBytes = Bytes.copyFrom(X25519.publicFromPrivate(privateKeyBytes));

    HpkePublicKey publicKey =
        HpkePublicKey.create(params, publicKeyBytes, /* idRequirement= */ 123);
    HpkePrivateKey privateKey =
        HpkePrivateKey.create(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    assertThat(publicKey.equalsKey(privateKey)).isFalse();
  }
}
