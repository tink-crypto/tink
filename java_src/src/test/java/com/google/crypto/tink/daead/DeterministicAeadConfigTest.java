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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for DeterministicAeadConfig. */
@RunWith(JUnit4.class)
public class DeterministicAeadConfigTest {

  @Test
  public void notOnlyFips_shouldRegisterAllKeyTypes() throws Exception {
    Assume.assumeFalse(TinkFips.useOnlyFips());

    DeterministicAeadConfig.register();

    assertThat(KeysetHandle.generateNew(PredefinedDeterministicAeadParameters.AES256_SIV))
        .isNotNull();
  }

  @Test
  public void onlyFips_shouldNotRegisterNonFipsKeyTypes() throws Exception {
    Assume.assumeTrue(TinkFips.useOnlyFips());

    DeterministicAeadConfig.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(PredefinedDeterministicAeadParameters.AES256_SIV));
  }
}
