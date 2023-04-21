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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class HmacPrfKeyTest {
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
  public void buildAndGetPropertiesVariedValues_succeeds(
      @FromDataPoints("keySizes") int keySize,
      @FromDataPoints("hashTypes") HmacPrfParameters.HashType hashType)
      throws Exception {
    HmacPrfParameters parameters =
        HmacPrfParameters.builder().setKeySizeBytes(keySize).setHashType(hashType).build();
    assertThat(parameters.hasIdRequirement()).isFalse();
    SecretBytes keyBytes = SecretBytes.randomBytes(keySize);
    HmacPrfKey key = HmacPrfKey.builder().setParameters(parameters).setKeyBytes(keyBytes).build();

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildWithoutSettingParameters_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> HmacPrfKey.builder().setKeyBytes(SecretBytes.randomBytes(16)).build());
  }

  @Test
  public void buildWithoutSettingKeyBytes_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacPrfKey.builder()
                .setParameters(
                    HmacPrfParameters.builder()
                        .setKeySizeBytes(16)
                        .setHashType(HmacPrfParameters.HashType.SHA256)
                        .build())
                .build());
  }

  @Test
  public void buildWithKeySizeMismatch_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            HmacPrfKey.builder()
                .setParameters(
                    HmacPrfParameters.builder()
                        .setKeySizeBytes(16)
                        .setHashType(HmacPrfParameters.HashType.SHA256)
                        .build())
                .setKeyBytes(SecretBytes.randomBytes(32))
                .build());
  }

  @Test
  public void equals() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    SecretBytes keyBytesCopy =
        SecretBytes.copyFrom(
            keyBytes.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    HmacPrfParameters parameters16 =
        HmacPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();
    HmacPrfParameters parameters32 =
        HmacPrfParameters.builder()
            .setKeySizeBytes(32)
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .build();

    new KeyTester()
        .addEqualityGroup(
            "16-byte key",
            HmacPrfKey.builder().setParameters(parameters16).setKeyBytes(keyBytes).build(),
            // Same key built twice.
            HmacPrfKey.builder().setParameters(parameters16).setKeyBytes(keyBytes).build(),
            // Same key built with a copy of the key bytes.
            HmacPrfKey.builder().setParameters(parameters16).setKeyBytes(keyBytesCopy).build())
        .addEqualityGroup(
            "16-byte random key bytes",
            HmacPrfKey.builder()
                .setParameters(parameters16)
                .setKeyBytes(SecretBytes.randomBytes(16))
                .build())
        .addEqualityGroup(
            "32-byte random key bytes",
            HmacPrfKey.builder()
                .setParameters(parameters32)
                .setKeyBytes(SecretBytes.randomBytes(32))
                .build())
        .addEqualityGroup(
            "different key class",
            HkdfPrfKey.builder()
                .setParameters(
                    HkdfPrfParameters.builder()
                        .setKeySizeBytes(16)
                        .setHashType(HkdfPrfParameters.HashType.SHA256)
                        .build())
                .setKeyBytes(keyBytes)
                .build())
        .doTests();
  }
}
