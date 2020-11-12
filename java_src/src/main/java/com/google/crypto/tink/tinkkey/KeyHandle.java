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

import java.security.GeneralSecurityException;

/**
 * Wraps a {@code TinkKey} and enforces access to the underlying {@code TinkKey} with {@code
 * KeyAccess}. Specifically, if the underlying {@code TinkKey} has a secret, then one can only get
 * it with a {@code SecretKeyAccess} instance.
 */
public final class KeyHandle {

  /**
   * Returns a {@code KeyHandle} instance with {@code key} as the underlying {@code TinkKey} if the
   * caller provides the correct {@code KeyAccess} instance.
   *
   * @throws GeneralSecurityException if {@code access} does not grant access to {@code key}
   */
  public static KeyHandle createFromKey(TinkKey key, KeyAccess access)
      throws GeneralSecurityException {
    KeyHandle result = new KeyHandle(key);
    result.checkAccess(access);
    return result;
  }

  private final TinkKey key;

  private KeyHandle(TinkKey key) {
    this.key = key;
  }

  /** Returns {@code true} if the underlying {@code TinkKey} has a secret. */
  public boolean hasSecret() {
    return key.hasSecret();
  }

  /**
   * Returns the underlying {@code TinkKey} key if {@code access} is a {@code SecretKeyAccess} and
   * the key has a secret, or if the key does not have a secret, otherwise throws a {@code
   * GeneralSecurityException}.
   */
  public TinkKey getKey(KeyAccess access) throws GeneralSecurityException {
    checkAccess(access);
    return key;
  }

  private void checkAccess(KeyAccess access) throws GeneralSecurityException {
    if (hasSecret() && !access.canAccessSecret()) {
      throw new GeneralSecurityException("No access");
    }
  }
}
