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
public final class AesCmacPrfKeyTest {
  @DataPoints("keySizes")
  public static final int[] KEY_SIZES = new int[] {16, 32};

  @Theory
  public void createAndGetProperties_succeeds(@FromDataPoints("keySizes") int keySize)
      throws Exception {
    AesCmacPrfParameters parameters = AesCmacPrfParameters.create(keySize);
    assertThat(parameters.hasIdRequirement()).isFalse();
    SecretBytes keyBytes = SecretBytes.randomBytes(keySize);
    AesCmacPrfKey key = AesCmacPrfKey.create(parameters, keyBytes);

    assertThat(key.getParameters()).isEqualTo(parameters);
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void createWithKeySizeMismatch_fails() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacPrfKey.create(AesCmacPrfParameters.create(16), SecretBytes.randomBytes(32)));
  }

  @Test
  public void equals() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(16);
    SecretBytes keyBytesCopy =
        SecretBytes.copyFrom(
            keyBytes.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    AesCmacPrfParameters parameters16 = AesCmacPrfParameters.create(16);
    AesCmacPrfParameters parameters32 = AesCmacPrfParameters.create(32);

    new KeyTester()
        .addEqualityGroup(
            "16-byte key",
            AesCmacPrfKey.create(parameters16, keyBytes),
            // Same key built twice.
            AesCmacPrfKey.create(parameters16, keyBytes),
            // Same key built with a copy of the key bytes.
            AesCmacPrfKey.create(parameters16, keyBytesCopy))
        .addEqualityGroup(
            "16-byte random key bytes",
            AesCmacPrfKey.create(parameters16, SecretBytes.randomBytes(16)))
        .addEqualityGroup(
            "32-byte random key bytes",
            AesCmacPrfKey.create(parameters32, SecretBytes.randomBytes(32)))
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
