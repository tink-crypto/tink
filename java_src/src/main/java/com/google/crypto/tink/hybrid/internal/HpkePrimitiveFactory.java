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

import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Helper class for creating HPKE primitives from either algorithm identifiers or {@link
 * com.google.crypto.tink.proto.HpkeParams}.
 */
final class HpkePrimitiveFactory {
  /** Returns an {@link HpkeKem} primitive corresponding to {@code kemId}. */
  static HpkeKem createKem(byte[] kemId) throws GeneralSecurityException {
    if (Arrays.equals(kemId, HpkeUtil.X25519_HKDF_SHA256_KEM_ID)) {
      return new X25519HpkeKem(new HkdfHpkeKdf("HmacSha256"));
    } else if (Arrays.equals(kemId, HpkeUtil.P256_HKDF_SHA256_KEM_ID)) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P256);
    } else if (Arrays.equals(kemId, HpkeUtil.P384_HKDF_SHA384_KEM_ID)) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P384);
    } else if (Arrays.equals(kemId, HpkeUtil.P521_HKDF_SHA512_KEM_ID)) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P521);
    }
    throw new IllegalArgumentException("Unrecognized HPKE KEM identifier");
  }

  /**
   * Returns an {@link HpkeKem} primitive corresponding to {@link
   * com.google.crypto.tink.proto.HpkeParams#getKem()}.
   */
  static HpkeKem createKem(HpkeParams params) throws GeneralSecurityException {
    if (params.getKem() == com.google.crypto.tink.proto.HpkeKem.DHKEM_X25519_HKDF_SHA256) {
      return new X25519HpkeKem(new HkdfHpkeKdf("HmacSha256"));
    } else if (params.getKem() == com.google.crypto.tink.proto.HpkeKem.DHKEM_P256_HKDF_SHA256) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P256);
    } else if (params.getKem() == com.google.crypto.tink.proto.HpkeKem.DHKEM_P384_HKDF_SHA384) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P384);
    } else if (params.getKem() == com.google.crypto.tink.proto.HpkeKem.DHKEM_P521_HKDF_SHA512) {
      return NistCurvesHpkeKem.fromCurve(EllipticCurves.CurveType.NIST_P521);
    }
    throw new IllegalArgumentException("Unrecognized HPKE KEM identifier");
  }

  /** Returns an {@link HpkeKdf} primitive corresponding to {@code kdfId}. */
  static HpkeKdf createKdf(byte[] kdfId) {
    if (Arrays.equals(kdfId, HpkeUtil.HKDF_SHA256_KDF_ID)) {
      return new HkdfHpkeKdf("HmacSha256");
    } else if (Arrays.equals(kdfId, HpkeUtil.HKDF_SHA384_KDF_ID)) {
      return new HkdfHpkeKdf("HmacSha384");
    } else if (Arrays.equals(kdfId, HpkeUtil.HKDF_SHA512_KDF_ID)) {
      return new HkdfHpkeKdf("HmacSha512");
    }
    throw new IllegalArgumentException("Unrecognized HPKE KDF identifier");
  }

  /**
   * Returns an {@link HpkeKdf} primitive corresponding to {@link
   * com.google.crypto.tink.proto.HpkeParams#getKdf()}.
   */
  static HpkeKdf createKdf(HpkeParams params) {
    if (params.getKdf() == com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA256) {
      return new HkdfHpkeKdf("HmacSha256");
    } else if (params.getKdf() == com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA384) {
      return new HkdfHpkeKdf("HmacSha384");
    } else if (params.getKdf() == com.google.crypto.tink.proto.HpkeKdf.HKDF_SHA512) {
      return new HkdfHpkeKdf("HmacSha512");
    }
    throw new IllegalArgumentException("Unrecognized HPKE KDF identifier");
  }

  /** Returns an {@link HpkeAead} primitive corresponding to {@code aeadId}. */
  static HpkeAead createAead(byte[] aeadId) throws GeneralSecurityException {
    if (Arrays.equals(aeadId, HpkeUtil.AES_128_GCM_AEAD_ID)) {
      return new AesGcmHpkeAead(16);
    } else if (Arrays.equals(aeadId, HpkeUtil.AES_256_GCM_AEAD_ID)) {
      return new AesGcmHpkeAead(32);
    } else if (Arrays.equals(aeadId, HpkeUtil.CHACHA20_POLY1305_AEAD_ID)) {
      return new ChaCha20Poly1305HpkeAead();
    }
    throw new IllegalArgumentException("Unrecognized HPKE AEAD identifier");
  }

  /**
   * Returns an {@link HpkeAead} primitive corresponding to {@link
   * com.google.crypto.tink.proto.HpkeParams#getAead()}.
   */
  static HpkeAead createAead(HpkeParams params) throws GeneralSecurityException {
    if (params.getAead() == com.google.crypto.tink.proto.HpkeAead.AES_128_GCM) {
      return new AesGcmHpkeAead(16);
    } else if (params.getAead() == com.google.crypto.tink.proto.HpkeAead.AES_256_GCM) {
      return new AesGcmHpkeAead(32);
    } else if (params.getAead() == com.google.crypto.tink.proto.HpkeAead.CHACHA20_POLY1305) {
      return new ChaCha20Poly1305HpkeAead();
    }
    throw new IllegalArgumentException("Unrecognized HPKE AEAD identifier");
  }

  private HpkePrimitiveFactory() {}
}
