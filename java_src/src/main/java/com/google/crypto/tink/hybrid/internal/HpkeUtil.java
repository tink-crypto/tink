// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import static com.google.crypto.tink.internal.Util.UTF_8;

import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;

/** Collection of helper functions for HPKE. */
public final class HpkeUtil {
  // HPKE mode identifiers.
  public static final byte[] BASE_MODE = intToByteArray(1, 0x0);
  public static final byte[] AUTH_MODE = intToByteArray(1, 0x2);

  // HPKE KEM algorithm identifiers.
  public static final byte[] X25519_HKDF_SHA256_KEM_ID = intToByteArray(2, 0x20);
  public static final byte[] P256_HKDF_SHA256_KEM_ID = intToByteArray(2, 0x10);
  public static final byte[] P384_HKDF_SHA384_KEM_ID = intToByteArray(2, 0x11);
  public static final byte[] P521_HKDF_SHA512_KEM_ID = intToByteArray(2, 0x12);

  // HPKE KDF algorithm identifiers.
  public static final byte[] HKDF_SHA256_KDF_ID = intToByteArray(2, 0x1);
  public static final byte[] HKDF_SHA384_KDF_ID = intToByteArray(2, 0x2);
  public static final byte[] HKDF_SHA512_KDF_ID = intToByteArray(2, 0x3);

  // HPKE AEAD algorithm identifiers.
  public static final byte[] AES_128_GCM_AEAD_ID = intToByteArray(2, 0x1);
  public static final byte[] AES_256_GCM_AEAD_ID = intToByteArray(2, 0x2);
  public static final byte[] CHACHA20_POLY1305_AEAD_ID = intToByteArray(2, 0x3);

  public static final byte[] EMPTY_SALT = new byte[0];

  private static final byte[] KEM = "KEM".getBytes(UTF_8);
  private static final byte[] HPKE = "HPKE".getBytes(UTF_8);
  private static final byte[] HPKE_V1 = "HPKE-v1".getBytes(UTF_8);

  /**
   * Transforms a passed value to an MSB first byte array with the size of the specified capacity.
   * (i.e., {@link com.google.crypto.tink.subtle.Bytes#intToByteArray(int, int)} with MSB first
   * instead of LSB first).
   *
   * <p>The HPKE standard defines this function as I2OSP(n, w) where w = capacity and n = value.
   *
   * <p>https://www.rfc-editor.org/rfc/rfc9180.html#name-notation
   *
   * @param capacity size of the resulting byte array
   * @param value that should be represented as a byte array
   */
  public static byte[] intToByteArray(int capacity, int value) {
    final byte[] result = new byte[capacity];
    for (int i = 0; i < capacity; i++) {
      result[i] = (byte) ((value >> (8 * (capacity - i - 1))) & 0xFF);
    }
    return result;
  }

  /**
   * Generates KEM suite id from {@code kemId} according to the definition in
   * https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-5. Only used for KEM suite id.
   *
   * @throws GeneralSecurityException when byte concatenation fails.
   */
  static byte[] kemSuiteId(byte[] kemId) throws GeneralSecurityException {
    return Bytes.concat(KEM, kemId);
  }

  /**
   * Generates HPKE suite id from {@code kemId}, {@code kdfId}, and {@code aeadId} according to the
   * definition in https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-8. Used for any non-KEM
   * suite id.
   *
   * @throws GeneralSecurityException when byte concatenation fails.
   */
  static byte[] hpkeSuiteId(byte[] kemId, byte[] kdfId, byte[] aeadId)
      throws GeneralSecurityException {
    return Bytes.concat(HPKE, kemId, kdfId, aeadId);
  }

  /**
   * Transforms {@code ikm} into labeled ikm using {@code label} and {@code suiteId} according to
   * {@code LabeledExtract()} defined in https://www.rfc-editor.org/rfc/rfc9180.html#section-4.
   *
   * @throws GeneralSecurityException when byte concatenation fails.
   */
  static byte[] labelIkm(String label, byte[] ikm, byte[] suiteId) throws GeneralSecurityException {
    return Bytes.concat(HPKE_V1, suiteId, label.getBytes(UTF_8), ikm);
  }

  /**
   * Transforms {@code info} into labeled info using {@code label}, {@code suiteId}, and {@code
   * length} according to {@code LabeledExpand()} defined in
   * https://www.rfc-editor.org/rfc/rfc9180.html#section-4.
   *
   * @throws GeneralSecurityException when byte concatenation fails.
   */
  static byte[] labelInfo(String label, byte[] info, byte[] suiteId, int length)
      throws GeneralSecurityException {
    return Bytes.concat(intToByteArray(2, length), HPKE_V1, suiteId, label.getBytes(UTF_8), info);
  }

  static EllipticCurves.CurveType nistHpkeKemToCurve(HpkeKem kem) throws GeneralSecurityException {
    switch (kem) {
      case DHKEM_P256_HKDF_SHA256:
        return EllipticCurves.CurveType.NIST_P256;
      case DHKEM_P384_HKDF_SHA384:
        return EllipticCurves.CurveType.NIST_P384;
      case DHKEM_P521_HKDF_SHA512:
        return EllipticCurves.CurveType.NIST_P521;
      default:
        throw new GeneralSecurityException("Unrecognized NIST HPKE KEM identifier");
    }
  }

  static EllipticCurves.CurveType nistHpkeKemToCurve(HpkeParameters.KemId kemId)
      throws GeneralSecurityException {
    if (kemId == HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256) {
      return EllipticCurves.CurveType.NIST_P256;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384) {
      return EllipticCurves.CurveType.NIST_P384;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512) {
      return EllipticCurves.CurveType.NIST_P521;
    }
    throw new GeneralSecurityException("Unrecognized NIST HPKE KEM identifier");
  }

  /** Lengths from 'Npk' column in https://www.rfc-editor.org/rfc/rfc9180.html#table-2. */
  public static int getEncodedPublicKeyLength(HpkeKem kem) throws GeneralSecurityException {
    switch (kem) {
      case DHKEM_X25519_HKDF_SHA256:
        return 32;
      case DHKEM_P256_HKDF_SHA256:
        return 65;
      case DHKEM_P384_HKDF_SHA384:
        return 97;
      case DHKEM_P521_HKDF_SHA512:
        return 133;
      default:
        throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
    }
  }

  /**
   * Returns the encapsulated key length (in bytes) for the specified {@code kemProtoEnum}. This
   * value corresponds to the 'Nenc' column in the following table.
   *
   * <p>https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism.
   */
  public static int encodingSizeInBytes(HpkeKem kemProtoEnum) {
    switch (kemProtoEnum) {
      case DHKEM_X25519_HKDF_SHA256:
        return 32;
      case DHKEM_P256_HKDF_SHA256:
        return 65;
      case DHKEM_P384_HKDF_SHA384:
        return 97;
      case DHKEM_P521_HKDF_SHA512:
        return 133;
      default:
        throw new IllegalArgumentException(
            "Unable to determine KEM-encoding length for " + kemProtoEnum.name());
    }
  }

  /**
   * Returns the encapsulated key length (in bytes) for the specified {@code kemId}. This value
   * corresponds to the 'Nenc' column in the following table.
   *
   * <p>https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism.
   */
  public static int encodingSizeInBytes(HpkeParameters.KemId kemId) {
    if (kemId == HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256) {
      return 32;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256) {
      return 65;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384) {
      return 97;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512) {
      return 133;
    }
    throw new IllegalArgumentException("Unable to determine KEM-encoding length for " + kemId);
  }

  /** Lengths from 'Nsk' column in https://www.rfc-editor.org/rfc/rfc9180.html#table-2. */
  public static int getEncodedPrivateKeyLength(HpkeKem kem) throws GeneralSecurityException {
    switch (kem) {
      case DHKEM_X25519_HKDF_SHA256:
        return 32;
      case DHKEM_P256_HKDF_SHA256:
        return 32;
      case DHKEM_P384_HKDF_SHA384:
        return 48;
      case DHKEM_P521_HKDF_SHA512:
        return 66;
      default:
        throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
    }
  }

  /** Lengths from 'Nsk' column in https://www.rfc-editor.org/rfc/rfc9180.html#table-2. */
  public static int getEncodedPrivateKeyLength(HpkeParameters.KemId kemId)
      throws GeneralSecurityException {
    if (kemId == HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256) {
      return 32;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256) {
      return 32;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384) {
      return 48;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512) {
      return 66;
    }
    throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
  }

  private HpkeUtil() {}
}
