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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for SignatureConfig. */
@RunWith(JUnit4.class)
public class SignatureConfigTest {

  @BeforeClass
  public static void setup() {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // This test may be run without onlyFips turned on, in which case it is fine that installing
      // conscrypt fails.
    }
  }

  @Test
  public void notOnlyFips_shouldRegisterAllKeyTypes() throws Exception {
    Assume.assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    SignatureConfig.register();

    assertThat(KeysetHandle.generateNew(PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4))
        .isNotNull();
    assertThat(
            KeysetHandle.generateNew(
                PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4))
        .isNotNull();
    assertThat(KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256)).isNotNull();
    assertThat(KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519)).isNotNull();
  }

  @Test
  public void onlyFips_shouldRegisterFipsKeyTypes() throws Exception {
    Assume.assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    SignatureConfig.register();

    assertThat(KeysetHandle.generateNew(PredefinedSignatureParameters.RSA_SSA_PKCS1_3072_SHA256_F4))
        .isNotNull();
    assertThat(
            KeysetHandle.generateNew(
                PredefinedSignatureParameters.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4))
        .isNotNull();
    assertThat(KeysetHandle.generateNew(PredefinedSignatureParameters.ECDSA_P256)).isNotNull();
  }

  @Test
  public void onlyFips_shouldNotRegisterNonFipsKeyTypes() throws Exception {
    Assume.assumeFalse(TestUtil.isTsan()); // KeysetHandle.generateNew is too slow in Tsan.
    Assume.assumeTrue(TinkFips.useOnlyFips());
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    SignatureConfig.register();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.generateNew(PredefinedSignatureParameters.ED25519));
  }
}
