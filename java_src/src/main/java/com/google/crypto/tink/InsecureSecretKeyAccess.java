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

package com.google.crypto.tink;

import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.errorprone.annotations.Immutable;

/** A helper class to create {@link SecretKeyAccess} tokens. */
@CheckReturnValue
@Alpha
@Immutable
public final class InsecureSecretKeyAccess {
  private InsecureSecretKeyAccess() {}

  /**
   * Returns a {@link SecretKeyAccess} token.
   *
   * <p>The token can be used to access secret key material. Within Google, access to this function
   * is restricted by the build system. Outside of Google, users can search their codebase for
   * "InsecureSecretKeyAccess" to find instances where it is used.
   */
  public static SecretKeyAccess get() {
    return SecretKeyAccess.instance();
  }
}
