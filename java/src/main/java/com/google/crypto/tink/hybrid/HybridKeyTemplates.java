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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadDemParams;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.ByteString;

/**
 * Pre-generated {@code KeyTemplate} for {@code HybridDecrypt} and {@code HybridEncrypt}
 * primitives. One can use these templates to generate new {@code Keyset} with
 * {@code KeysetHandle}. To generate a new keyset that contains a single
 * {@code EciesAeadHkdfPrivateKey}, one can do:
 * <pre>
 *   Config.register(HybridConfig.TINK_1_0_0);
 *   KeysetHandle handle = KeysetHandle.generateNew(
 *       HybridKeyTemplates.ECIES_P256_HKDF_AES128_GCM);
 *   PublicKeySign signer = PublicKeySignFactory.getPrimitive(handle);
 * </pre>
 */
public final class HybridKeyTemplates {
  private static final byte[] EMPTY_SALT = new byte[0];
  /**
   * A {@code KeyTemplate} that generates new instances of {@code EciesAeadHkdfPrivateKey}
   * with the following parameters:
   *   - KEM: ECDH over NIST P-256
   *   - DEM: AES128-GCM
   *   - KDF: HKDF-HMAC-SHA256 with empty salt
   */
  public static final KeyTemplate ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM =
      createEciesAeadHkdfKeyTemplate(
          EllipticCurveType.NIST_P256, HashType.SHA256, EcPointFormat.UNCOMPRESSED,
          AeadKeyTemplates.AES128_GCM, EMPTY_SALT);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code EciesAeadHkdfPrivateKey}
   * with the following parameters:
   *   - KEM: ECDH over NIST P-256
   *   - DEM: AES128-CTR-HMAC-SHA256 with the following parameters:
   *     - AES key size: 128 bits
   *     - IV size: 128 bits
   *     - HMAC key size: 256 bits
   *     - HMAC tag size: 128 bits
   *   - KDF: HKDF-HMAC-SHA256 with empty salt
   */
  public static final KeyTemplate
      ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256 =
          createEciesAeadHkdfKeyTemplate(
              EllipticCurveType.NIST_P256, HashType.SHA256, EcPointFormat.UNCOMPRESSED,
              AeadKeyTemplates.AES128_CTR_HMAC_SHA256, EMPTY_SALT);

  /**
   *  @return a {@code KeyTemplate} containing a {code EciesAeadHkdfKeyFormat}.
   */
  public static KeyTemplate createEciesAeadHkdfKeyTemplate(EllipticCurveType curve,
      HashType hashType, EcPointFormat ecPointFormat, KeyTemplate demKeyTemplate,
      byte[] salt) {
    EciesAeadHkdfKeyFormat format = EciesAeadHkdfKeyFormat.newBuilder()
        .setParams(
            createEciesAeadHkdfParams(curve, hashType, ecPointFormat, demKeyTemplate, salt))
        .build();
    return KeyTemplate.newBuilder()
        .setTypeUrl(EciesAeadHkdfPrivateKeyManager.TYPE_URL)
        .setValue(format.toByteString())
        .build();
  }

  /**
   *  @return a {@code EciesAeadHkdfParams} with the specified parameters.
   */
  public static EciesAeadHkdfParams createEciesAeadHkdfParams(EllipticCurveType curve,
      HashType hashType, EcPointFormat ecPointFormat, KeyTemplate demKeyTemplate,
      byte[] salt) {
    EciesHkdfKemParams kemParams = EciesHkdfKemParams.newBuilder()
        .setCurveType(curve)
        .setHkdfHashType(hashType)
        .setHkdfSalt(ByteString.copyFrom(salt))
        .build();
    EciesAeadDemParams demParams = EciesAeadDemParams.newBuilder()
        .setAeadDem(demKeyTemplate)
        .build();
    return EciesAeadHkdfParams.newBuilder()
        .setKemParams(kemParams)
        .setDemParams(demParams)
        .setEcPointFormat(ecPointFormat)
        .build();
  }
}
