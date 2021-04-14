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
package com.google.crypto.tink.subtle;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.TinkFips;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for EngineFactory when Tink is build in FIPS-mode. */
@RunWith(JUnit4.class)
public final class EngineFactoryFipsTest {

  @Before
  public void setUp() throws Exception {
    // All tests here require that Tink is build in FIPS-mode.
    Assume.assumeTrue(TinkFips.useOnlyFips());

    // Register conscrypt
    Conscrypt.checkAvailability();
  }

  @Test
  public void testConscryptUsedAsProviderForCiphers() throws Exception {
    Provider p = Conscrypt.newProvider();
    Security.addProvider(p);
    String conscryptName = p.getName();

    assertThat(EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.CIPHER.getInstance("AES/CTR/NoPadding").getProvider().getName())
        .isEqualTo(conscryptName);
  }

  @Test
  public void testConscryptUsedAsProviderForMac() throws Exception {
    Provider p = Conscrypt.newProvider();
    Security.addProvider(p);
    String conscryptName = p.getName();

    assertThat(EngineFactory.MAC.getInstance("HMACSHA1").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.MAC.getInstance("HMACSHA224").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.MAC.getInstance("HMACSHA256").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.MAC.getInstance("HMACSHA384").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.MAC.getInstance("HMACSHA512").getProvider().getName())
        .isEqualTo(conscryptName);
  }

  @Test
  public void testConscryptUsedAsProviderForSigner() throws Exception {
    Provider p = Conscrypt.newProvider();
    Security.addProvider(p);
    String conscryptName = p.getName();

    assertThat(EngineFactory.SIGNATURE.getInstance("SHA256withRSA").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA384withRSA").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA512withRSA").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA256withRSAandMGF1").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA384withRSAandMGF1").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA512withRSAandMGF1").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA256withECDSA").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA384withECDSA").getProvider().getName())
        .isEqualTo(conscryptName);
    assertThat(EngineFactory.SIGNATURE.getInstance("SHA512withECDSA").getProvider().getName())
        .isEqualTo(conscryptName);
  }

  @Test
  public void testNoFallback() throws Exception {
    Provider p = Conscrypt.newProvider();
    Security.addProvider(p);

    // Conscrypt does not provide "AES", so this must fail and not use another provider.
    assertThrows(GeneralSecurityException.class, () -> EngineFactory.CIPHER.getInstance("AES"));
  }
}
