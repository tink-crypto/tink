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
package com.google.crypto.tink.config.internal;

/**
 * Static methods for checking if Tink was built in FIPS mode and to check for algorithm
 * compatibility.
 */
public final class TinkFipsUtil {
  /** The status of FIPS compatibility of an algorithm. */
  public enum AlgorithmFipsCompatibility {
    /** The algorithm is not FIPS compatible */
    ALGORITHM_NOT_FIPS {
      @Override
      public boolean isCompatible() {
        // Non-FIPS algorithms are only allowed if Tink is not built in FIPS-only mode.
        return !TinkFipsStatus.useOnlyFips();
      }
    },
    /** The algorithm has a FIPS validated implementation if BoringCrypto is available. */
    ALGORITHM_REQUIRES_BORINGCRYPTO {
      @Override
      public boolean isCompatible() {
        // If Tink is not in FIPS-only mode, then no restrictions are necessary. In FIPS-only mode
        // this returns True if BoringCrypto is available.
        return !TinkFipsStatus.useOnlyFips() || TinkFipsStatus.fipsModuleAvailable();
      }
    };

    public abstract boolean isCompatible();
  }

  public static boolean useOnlyFips() {
    return TinkFipsStatus.useOnlyFips();
  }

  public static boolean fipsModuleAvailable() {
    return TinkFipsStatus.fipsModuleAvailable();
  }

  private TinkFipsUtil() {}

}
