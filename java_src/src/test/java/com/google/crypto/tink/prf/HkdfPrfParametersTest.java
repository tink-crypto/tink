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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class HkdfPrfParametersTest {

  private static final Bytes SALT = Bytes.copyFrom(TestUtil.hexDecode("2023af"));

  @DataPoints("keySizes")
  public static final int[] KEY_SIZES = new int[] {16, 32};

  @Theory
  public void buildWithSalt_succeeds(@FromDataPoints("keySizes") int keySize) throws Exception {
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(keySize)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setSalt(SALT)
            .build();
    assertThat(parameters.getKeySizeBytes()).isEqualTo(keySize);
    assertThat(parameters.getHashType()).isEqualTo(HkdfPrfParameters.HashType.SHA256);
    assertThat(parameters.getSalt()).isEqualTo(SALT);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.toString())
        .isEqualTo(
            "HKDF PRF Parameters (hashType: SHA256, salt: Bytes(2023af), and "
                + keySize
                + "-byte key)");
  }

  @Test
  public void buildWithoutSettingSalt_succeeds() throws Exception {
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    assertThat(parameters.getSalt()).isNull();
  }

  @Test
  public void buildWithEmptySalt_succeeds() throws Exception {
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setSalt(Bytes.copyFrom("".getBytes(UTF_8)))
            .build();
    assertThat(parameters.getSalt()).isNull();
  }

  @Test
  public void buildWithoutSettingKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HkdfPrfParameters.builder()
                .setHashType(HkdfPrfParameters.HashType.SHA256)
                .setSalt(SALT)
                .build());
  }

  @Test
  public void buildWithUnsupportedKeySize_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HkdfPrfParameters.builder()
                .setKeySizeBytes(15)
                .setHashType(HkdfPrfParameters.HashType.SHA256)
                .setSalt(SALT)
                .build());
  }

  @Test
  public void buildWithoutSettingHashType_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> HkdfPrfParameters.builder().setKeySizeBytes(16).setSalt(SALT).build());
  }

  @Test
  public void equalsAndHashCode() throws Exception {
    HkdfPrfParameters parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setSalt(SALT)
            .build();
    HkdfPrfParameters sameParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setSalt(SALT)
            .build();
    assertThat(sameParameters).isEqualTo(parameters);
    assertThat(sameParameters.hashCode()).isEqualTo(parameters.hashCode());

    HkdfPrfParameters keySize32Parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(parameters.getHashType())
            .setSalt(parameters.getSalt())
            .build();
    assertThat(keySize32Parameters).isNotEqualTo(parameters);
    assertThat(keySize32Parameters.hashCode()).isNotEqualTo(parameters.hashCode());

    HkdfPrfParameters sha512Parameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(parameters.getKeySizeBytes())
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setSalt(parameters.getSalt())
            .build();
    assertThat(sha512Parameters).isNotEqualTo(parameters);
    assertThat(sha512Parameters.hashCode()).isNotEqualTo(parameters.hashCode());

    HkdfPrfParameters noSaltParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(parameters.getKeySizeBytes())
            .setHashType(parameters.getHashType())
            .build();
    HkdfPrfParameters sameNoSaltParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(parameters.getKeySizeBytes())
            .setHashType(parameters.getHashType())
            .build();
    assertThat(sameNoSaltParameters).isEqualTo(noSaltParameters);
    assertThat(sameNoSaltParameters.hashCode()).isEqualTo(noSaltParameters.hashCode());
    assertThat(noSaltParameters).isNotEqualTo(parameters);
    assertThat(noSaltParameters.hashCode()).isNotEqualTo(parameters.hashCode());
  }
}
