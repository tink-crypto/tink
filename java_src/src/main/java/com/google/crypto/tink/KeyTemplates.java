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

package com.google.crypto.tink;

import java.security.GeneralSecurityException;

/**
 * This class consists exclusively of static methods that load {@link KeyTemplate} objects.
 *
 * @since 1.6.0
 */
public final class KeyTemplates {

  /**
   * Returns a key template that was registered with the {@link Registry} as {@code name}.
   *
   * @throws GeneralSecurityException if cannot find key template with name {@code name} in the
   *     Registry
   * @since 1.6.0
   */
  public static KeyTemplate get(String name) throws GeneralSecurityException {
    KeyTemplate result = Registry.keyTemplateMap().get(name);
    if (result == null) {
      throw new GeneralSecurityException("cannot find key template: " + name);
    } else {
      return result;
    }
  }

  private KeyTemplates() {}
}
