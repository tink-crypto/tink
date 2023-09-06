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
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for JwtSignatureConfigTest. */
@RunWith(JUnit4.class)
public class JwtSignatureConfigTest {

  @Test
  public void failIfAndOnlyIfInInvalidFipsState() throws Exception {
    boolean invalidFipsState = TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable();

    if (invalidFipsState) {
      assertThrows(GeneralSecurityException.class, JwtSignatureConfig::register);
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(KeyTemplates.get("JWT_ES256")));
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(KeyTemplates.get("JWT_RS256_2048_F4")));
      assertThrows(
          GeneralSecurityException.class,
          () -> KeysetHandle.generateNew(KeyTemplates.get("JWT_PS256_2048_F4")));

    } else {
      if (TinkFips.useOnlyFips()) {
        // TODO(b/298896710): This currently fails, but this is a bug.
        assertThrows(GeneralSecurityException.class, JwtSignatureConfig::register);
        return;
      }
      JwtSignatureConfig.register();
      assertNotNull(KeysetHandle.generateNew(KeyTemplates.get("JWT_ES256")));
      assertNotNull(KeysetHandle.generateNew(KeyTemplates.get("JWT_RS256_2048_F4")));
      assertNotNull(KeysetHandle.generateNew(KeyTemplates.get("JWT_PS256_2048_F4")));
    }
  }
}
