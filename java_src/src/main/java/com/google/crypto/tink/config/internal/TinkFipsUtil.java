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

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Static methods for checking if Tink was built in FIPS mode and to check for algorithm
 * compatibility.
 */
public final class TinkFipsUtil {

  // Is true if the FIPS restrictions have been enabled at runtime.
  private static final AtomicBoolean isRestrictedToFips = new AtomicBoolean(false);

  /** The status of FIPS compatibility of an algorithm. */
  public enum AlgorithmFipsCompatibility {
    /** The algorithm is not FIPS compatible */
    ALGORITHM_NOT_FIPS {
      @Override
      public boolean isCompatible() {
        // Non-FIPS algorithms are only allowed if Tink is not built in FIPS-only mode.
        return !useOnlyFips();
      }
    },
    /** The algorithm has a FIPS validated implementation if BoringCrypto is available. */
    ALGORITHM_REQUIRES_BORINGCRYPTO {
      @Override
      public boolean isCompatible() {
        // If Tink is not in FIPS-only mode, then no restrictions are necessary. In FIPS-only mode
        // this returns True if BoringCrypto is available.
        return !useOnlyFips() || fipsModuleAvailable();
      }
    };

    public abstract boolean isCompatible();
  }

  public static void setFipsRestricted() {
    isRestrictedToFips.set(true);
  }

  /**
   * This method is only exposed for tests and should not be used to disable the FIPS restrictions.
   */
  public static void unsetFipsRestricted() {
    isRestrictedToFips.set(false);
  }

  public static boolean useOnlyFips() {
    return TinkFipsStatus.useOnlyFips() || isRestrictedToFips.get();
  }

  public static boolean fipsModuleAvailable() {
    return checkConscryptIsAvailableAndUsesFipsBoringSsl();
  }

  static Boolean checkConscryptIsAvailableAndUsesFipsBoringSsl() {
    try {
      Class<?> cls = Class.forName("org.conscrypt.Conscrypt");
      Method isBoringSslFIPSBuild = cls.getMethod("isBoringSslFIPSBuild");
      return (Boolean) isBoringSslFIPSBuild.invoke(null);
    } catch (ReflectiveOperationException e) {
      // For older versions of Conscrypt we get a NoSuchMethodException. But no matter what goes
      // wrong, we cannot guarantee that Conscrypt uses BoringCrypto, so we will return false.
      return false;
    }
  }

  private TinkFipsUtil() {}

}
