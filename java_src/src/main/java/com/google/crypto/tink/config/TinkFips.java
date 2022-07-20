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
package com.google.crypto.tink.config;

import com.google.crypto.tink.Registry;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;

/**
 * Static methods for checking if Tink has been built in FIPS-mode.
 */
public final class TinkFips {
  /**
   * Returns true if the FIPS-mode has been enabled at build time or runtime.
   */
  public static boolean useOnlyFips() {
    return TinkFipsUtil.useOnlyFips();
  }

  public static void restrictToFips() throws GeneralSecurityException {
    Registry.restrictToFipsIfEmpty();
  }

  private TinkFips() {}
}
