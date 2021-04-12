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

/**
 * This is a dummy class matching the file name for Java which is not used. This file is only
 * included in a build if Tink is not built in FIPS-only mode to provide the TinkFipsStatus class.
 */
final class TinkFipsDisabled {}

final class TinkFipsStatus {
  public static boolean useOnlyFips() {
    return false;
  }

  public static boolean fipsModuleAvailable() {
    return false;
  }

  private TinkFipsStatus() {}
}
