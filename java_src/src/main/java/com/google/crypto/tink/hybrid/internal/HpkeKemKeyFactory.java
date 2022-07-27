// Copyright 2022 Google LLC
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

import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;

/** Helper class for creating HPKE KEM asymmetric keys. */
final class HpkeKemKeyFactory {

  private static EllipticCurves.CurveType nistHpkeKemToCurve(HpkeKem kem)
      throws GeneralSecurityException {
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

  static HpkeKemPrivateKey createPrivate(HpkePrivateKey privateKey)
      throws GeneralSecurityException {
    switch (privateKey.getPublicKey().getParams().getKem()) {
      case DHKEM_X25519_HKDF_SHA256:
        return X25519HpkeKemPrivateKey.fromBytes(privateKey.getPrivateKey().toByteArray());
      case DHKEM_P256_HKDF_SHA256:
      case DHKEM_P384_HKDF_SHA384:
      case DHKEM_P521_HKDF_SHA512:
        return NistCurvesHpkeKemPrivateKey.fromBytes(
            privateKey.getPrivateKey().toByteArray(),
            privateKey.getPublicKey().getPublicKey().toByteArray(),
            nistHpkeKemToCurve(privateKey.getPublicKey().getParams().getKem()));
      default:
        throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
    }
  }

  private HpkeKemKeyFactory() {}
}
