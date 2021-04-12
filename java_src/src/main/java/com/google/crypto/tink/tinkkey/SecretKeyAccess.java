// Copyright 2020 Google LLC
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
package com.google.crypto.tink.tinkkey;

import com.google.errorprone.annotations.Immutable;

/**
 * A class used to generate {@code KeyAccess} instances granting secret access.
 *
 * <p>This class can be used to keep track of places where secret keys are accessed directly in
 * code, as opposed to indirectly via a primitive.
 **/
@Immutable
public final class SecretKeyAccess {

  private SecretKeyAccess() {}

  /**
   * Returns a {@code KeyAccess} instance where {@code canAccessSecret()} returns true.
   **/
  public static KeyAccess insecureSecretAccess() {
    return KeyAccess.secretAccess();
  }
}
