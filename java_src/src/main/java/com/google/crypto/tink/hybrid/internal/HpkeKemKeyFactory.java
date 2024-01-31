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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import java.security.GeneralSecurityException;

/** Helper class for creating HPKE KEM asymmetric keys. */
public final class HpkeKemKeyFactory {
  @AccessesPartialKey
  public static HpkeKemPrivateKey createPrivate(HpkePrivateKey privateKey)
      throws GeneralSecurityException {
    HpkeParameters.KemId kemId = privateKey.getParameters().getKemId();
    if (kemId == HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256) {
      return X25519HpkeKemPrivateKey.fromBytes(
          privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()));
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256
        || kemId == HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384
        || kemId == HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512) {
      return NistCurvesHpkeKemPrivateKey.fromBytes(
          privateKey.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
          privateKey.getPublicKey().getPublicKeyBytes().toByteArray(),
          HpkeUtil.nistHpkeKemToCurve(kemId));
    }
    throw new GeneralSecurityException("Unrecognized HPKE KEM identifier");
  }

  private HpkeKemKeyFactory() {}
}
