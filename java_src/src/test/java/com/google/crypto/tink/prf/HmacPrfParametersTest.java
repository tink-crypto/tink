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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class HmacPrfParametersTest {
  @DataPoints("keySizes")
  public static final int[] KEY_SIZES = new int[] {16, 32};

  @DataPoints("hashTypes")
  public static final HmacPrfParameters.HashType[] HASH_TYPES =
      new HmacPrfParameters.HashType[] {
        HmacPrfParameters.HashType.SHA1,
        HmacPrfParameters.HashType.SHA224,
        HmacPrfParameters.HashType.SHA256,
        HmacPrfParameters.HashType.SHA384,
        HmacPrfParameters.HashType.SHA512
      };

  @Theory
  public void buildParametersVariedValuesAndGetProperties(
      @FromDataPoints("keySizes") int keySize,
      @FromDataPoints("hashTypes") HmacPrfParameters.HashType hashType)
      throws Exception {
    HmacPrfParameters parameters =
        HmacPrfParameters.builder().setKeySizeBytes(keySize).setHashType(hashType).build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(keySize);
    assertThat(parameters.getHashType()).isEqualTo(hashType);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.toString())
        .isEqualTo("HMAC PRF Parameters (hashType: " + hashType + " and " + keySize + "-byte key)");
  }

  @Test
  public void buildWithoutSettingKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> HmacPrfParameters.builder().setHashType(HmacPrfParameters.HashType.SHA256).build());
  }

  @Test
  public void buildWithUnsupportedKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacPrfParameters.builder()
                .setKeySizeBytes(15)
                .setHashType(HmacPrfParameters.HashType.SHA256)
                .build());
  }

  @Test
  public void buildWithoutSettingHashType_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> HmacPrfParameters.builder().setKeySizeBytes(16).build());
  }

  @Test
  public void testEqualsAndHashCode() throws Exception {
    HmacPrfParameters parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfParameters sameParameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    assertThat(sameParameters).isEqualTo(parameters);
    assertThat(sameParameters.hashCode()).isEqualTo(parameters.hashCode());

    // Different key size
    HmacPrfParameters keySize32Parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(parameters.getHashType())
            .build();
    assertThat(keySize32Parameters).isNotEqualTo(parameters);
    assertThat(keySize32Parameters.hashCode()).isNotEqualTo(parameters.hashCode());

    // Different hash type
    HmacPrfParameters sha512Parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(parameters.getKeySizeBytes())
            .setHashType(HmacPrfParameters.HashType.SHA512)
            .build();
    assertThat(sha512Parameters).isNotEqualTo(parameters);
    assertThat(sha512Parameters.hashCode()).isNotEqualTo(parameters.hashCode());
  }

  @Test
  @SuppressWarnings("TruthIncompatibleType")
  public void testEqualDifferentClass() throws Exception {
    HmacPrfParameters hmacPrfParameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    assertThat(hmacPrfParameters).isNotEqualTo(hkdfPrfParameters);
  }
}
