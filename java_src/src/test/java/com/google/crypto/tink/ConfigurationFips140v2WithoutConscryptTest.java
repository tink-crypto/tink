// Copyright 2024 Google LLC
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

package com.google.crypto.tink;

import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** This test ensures that ConfigurationFips140v2 is not created if Conscrypt is not registered. */
@RunWith(JUnit4.class)
public class ConfigurationFips140v2WithoutConscryptTest {

  @Test
  public void get_failsIfConscryptNotAvailable() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.fipsModuleAvailable());

    assertThrows(GeneralSecurityException.class, ConfigurationFips140v2::get);
  }
}
