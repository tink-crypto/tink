// Copyright 2021 Google LLC
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

package com.google.crypto.tink.keyderivation;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.prf.PredefinedPrfParameters;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeyDerivationConfig. */
@RunWith(JUnit4.class)
public class KeyDerivationConfigTest {

  @Test
  public void notOnlyFips_shouldBeRegistered() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    AeadConfig.register();
    KeyDerivationConfig.register();

    // Check that registration worked by generating a new key.
    PrfBasedKeyDerivationParameters prfBasedParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PredefinedPrfParameters.HKDF_SHA256)
            .setDerivedKeyParameters(PredefinedAeadParameters.AES128_GCM)
            .build();
    assertThat(KeysetHandle.generateNew(prfBasedParameters)).isNotNull();
  }

  @Test
  public void onlyFips_shouldNotBeRegistered() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    AeadConfig.register();
    KeyDerivationConfig.register();

    // Both the PRF and the Key Derivation key manager should not have been installed.
    // Check that this by verifying that key generation fails.
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(PredefinedPrfParameters.HKDF_SHA256));
    PrfBasedKeyDerivationParameters prfBasedParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(PredefinedPrfParameters.HKDF_SHA256)
            .setDerivedKeyParameters(PredefinedAeadParameters.AES128_GCM)
            .build();
    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.generateNew(prfBasedParameters));
  }
}
