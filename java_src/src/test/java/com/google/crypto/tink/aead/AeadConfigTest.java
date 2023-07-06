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

package com.google.crypto.tink.aead;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.junit.runners.MethodSorters;

/**
 * Tests for AeadConfig. Using FixedMethodOrder to ensure that aaaTestInitialization runs first, as
 * it tests execution of a static block within AeadConfig-class.
 */
@RunWith(JUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AeadConfigTest {

  @Test
  public void withoutFips_allAeadKeyTypesAreRegistered() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    AeadConfig.register();

    assertNotNull(KeysetHandle.generateNew(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256));
    assertNotNull(KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM));
    assertNotNull(KeysetHandle.generateNew(PredefinedAeadParameters.AES128_EAX));
    assertNotNull(KeysetHandle.generateNew(PredefinedAeadParameters.CHACHA20_POLY1305));
    assertNotNull(KeysetHandle.generateNew(PredefinedAeadParameters.XCHACHA20_POLY1305));
  }

  @Test
  public void withFips_fipsKeyTypesAreRegistered() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    AeadConfig.register();

    assertNotNull(KeysetHandle.generateNew(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256));
    assertNotNull(KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM));
  }

  @Test
  public void withFips_nonFipsKeyTypesAreNotRegistered() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    AeadConfig.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(PredefinedAeadParameters.AES128_EAX));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(AesGcmSivParameters.builder().setKeySizeBytes(16).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(PredefinedAeadParameters.CHACHA20_POLY1305));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(PredefinedAeadParameters.XCHACHA20_POLY1305));
  }
}
