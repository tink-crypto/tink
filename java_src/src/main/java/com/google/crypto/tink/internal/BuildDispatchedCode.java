// Copyright 2022 Google LLC
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

package com.google.crypto.tink.internal;

import javax.annotation.Nullable;

/**
 * Static utility functions which need to be compiled with different code in Android and Java.
 *
 * <p>This is the Java version. The android code can be found in
 * third_party/tink/java_src/src_android/main/java/com/google/crypto/tink/internal/BuildDispatchedCode.java
 */
final class BuildDispatchedCode {

  private BuildDispatchedCode() {}

  /** Returns the Android API level or null if in Java. */
  @Nullable
  public static Integer getApiLevel() {
    return null;
  }
}
