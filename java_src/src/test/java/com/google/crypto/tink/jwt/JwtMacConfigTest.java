// Copyright 2023 Google Inc.
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

package com.google.crypto.tink.jwt;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JwtMacConfigTest. */
@RunWith(JUnit4.class)
public class JwtMacConfigTest {

  @Test
  public void failIfAndOnlyIfInInvalidFipsState() throws Exception {
    boolean invalidFipsState = TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable();

    Parameters hs256Parameters =
        JwtHmacParameters.builder()
            .setKeySizeBytes(32)
            .setAlgorithm(JwtHmacParameters.Algorithm.HS256)
            .setKidStrategy(JwtHmacParameters.KidStrategy.IGNORED)
            .build();

    if (invalidFipsState) {
      assertThrows(GeneralSecurityException.class, JwtMacConfig::register);
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(KeyTemplates.get("JWT_HS256")));
      assertThrows(
          GeneralSecurityException.class,
          () -> MutableKeyCreationRegistry.globalInstance().createKey(hs256Parameters, null));
    } else {
      JwtMacConfig.register();
      assertNotNull(KeysetHandle.generateNew(KeyTemplates.get("JWT_HS256")));
      assertNotNull(MutableKeyCreationRegistry.globalInstance().createKey(hs256Parameters, null));
    }
  }
}
