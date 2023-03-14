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
public final class AesCmacPrfParametersTest {
  @DataPoints("keySizes")
  public static final int[] KEY_SIZES = new int[] {16, 32};

  @Theory
  public void createParametersAndGetProperties(@FromDataPoints("keySizes") int keySize)
      throws Exception {
    AesCmacPrfParameters parameters = AesCmacPrfParameters.create(keySize);
    assertThat(parameters.getKeySizeBytes()).isEqualTo(keySize);
    assertThat(parameters.hasIdRequirement()).isFalse();
    assertThat(parameters.toString())
        .isEqualTo("AesCmac PRF Parameters (" + keySize + "-byte key)");
  }

  @Test
  public void createWithUnsupportedKeySize_fails() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> AesCmacPrfParameters.create(19));
  }

  @Theory
  public void testEqualsAndHashCode(@FromDataPoints("keySizes") int keySize) throws Exception {
    AesCmacPrfParameters parameters = AesCmacPrfParameters.create(keySize);
    AesCmacPrfParameters sameParameters = AesCmacPrfParameters.create(keySize);

    assertThat(sameParameters).isEqualTo(parameters);
    assertThat(sameParameters.hashCode()).isEqualTo(parameters.hashCode());
  }

  @Test
  public void testEqualsAndHashCode_different() throws Exception {
    AesCmacPrfParameters parameters16 = AesCmacPrfParameters.create(16);
    AesCmacPrfParameters parameters32 = AesCmacPrfParameters.create(32);

    assertThat(parameters16).isNotEqualTo(parameters32);
    assertThat(parameters16.hashCode()).isNotEqualTo(parameters32.hashCode());
  }

  @Test
  @SuppressWarnings("TruthIncompatibleType")
  public void testEqualDifferentClass() throws Exception {
    AesCmacPrfParameters aesCmacPrfParameters = AesCmacPrfParameters.create(16);
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setKeySizeBytes(16)
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .build();
    assertThat(aesCmacPrfParameters).isNotEqualTo(hkdfPrfParameters);
  }
}
