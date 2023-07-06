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

package com.google.crypto.tink.config;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import com.google.crypto.tink.mac.PredefinedMacParameters;
import com.google.crypto.tink.signature.PredefinedSignatureParameters;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for TinkConfig. */
@RunWith(JUnit4.class)
public class TinkConfigTest {
  @Test
  public void registerWorks() throws Exception {
    TinkConfig.register();

    // Check that registration worked by generating a new key.
    assertThat(KeysetHandle.generateNew(PredefinedMacParameters.HMAC_SHA256_128BITTAG)).isNotNull();
    assertThat(KeysetHandle.generateNew(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256))
        .isNotNull();
    assertThat(KeysetHandle.generateNew(PredefinedDeterministicAeadParameters.AES256_SIV))
        .isNotNull();
    assertThat(KeysetHandle.generateNew(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM))
        .isNotNull();
    assertThat(KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256)).isNotNull();
    assertThat(KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES128_GCM_HKDF_4KB))
        .isNotNull();
  }
}
