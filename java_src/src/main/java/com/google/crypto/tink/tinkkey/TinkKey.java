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

import com.google.crypto.tink.KeyTemplate;
import com.google.errorprone.annotations.Immutable;

/**
 * {@code TinkKey} represents how Tink views individual keys. In contrast, {@code KeysetHandle} only
 * provides access to a {@code Keyset}, which represents multiple keys.
 *
 * <p> A {@code TinkKey} contains the data associated to a type of key and provides ways of getting
 * that data. The {@code TinkKey} interface does not specify how the key data is represented nor how
 * it provides access to the data.
**/
@Immutable
public interface TinkKey {
  /** Returns true if the key contains secret key material, and false otherwise. */
  public boolean hasSecret();

  /**
   * A {@code TinkKey} should know the {@code KeyTemplate} from which it was generated,
   * which in turn specifies the cryptographic algorithm in which the {@code TinkKey} should
   * be used.
   *
   * Throws UnsupportedOperationException to help ease rollout until it is possible to easily
   * find the KeyTemplate associated to a key described in proto
   *
   * @return the {@code KeyTemplate} used to generate the key.
   * @throws UnsupportedOperationException if the {@code TinkKey} does not yet support returning
   * its {@code KeyTemplate}
   **/

  public KeyTemplate getKeyTemplate();
}
