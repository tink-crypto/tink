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
import javax.crypto.Cipher;
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
  }

  @Test
  public void testConscryptUsedAsProvider() throws Exception {
    Conscrypt.checkAvailability();
    Provider p = Conscrypt.newProvider();
    Security.addProvider(p);
    Cipher c = EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding");
    assertThat(c.getProvider().getName()).isEqualTo(p.getName());
  }

  @Test
  public void testNoFallback() throws Exception {
    Conscrypt.checkAvailability();
    Security.addProvider(Conscrypt.newProvider());

    // Conscrypt does not provide "AES", so this must fail and not use another provider.
    assertThrows(GeneralSecurityException.class, () -> EngineFactory.CIPHER.getInstance("AES"));
  }
}
