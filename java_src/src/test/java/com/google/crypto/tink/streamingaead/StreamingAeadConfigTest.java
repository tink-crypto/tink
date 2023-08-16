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

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for StreamingAeadConfig. */
@RunWith(JUnit4.class)
public class StreamingAeadConfigTest {

  @Test
  public void notOnlyFips_shouldRegisterAllKeyTypes() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    StreamingAeadConfig.register();

    assertThat(KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM_HKDF_4KB"))).isNotNull();
    assertThat(KeysetHandle.generateNew(KeyTemplates.get("AES128_CTR_HMAC_SHA256_4KB")))
        .isNotNull();
  }

  @Test
  public void onlyFips_shouldNotRegisterNonFipsKeyTypes() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    StreamingAeadConfig.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM_HKDF_4KB")));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(KeyTemplates.get("AES128_CTR_HMAC_SHA256_4KB")));
  }
}
