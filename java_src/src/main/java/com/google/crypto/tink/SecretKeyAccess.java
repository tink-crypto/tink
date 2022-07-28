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
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Represents access to secret key material.
 *
 * <p>Tink restricts access to secret key material, and users who require such access need to have
 * an object of the class {@code SecretKeyAccess} to do this. For example, a function that outputs
 * individiual key bytes might look like this:
 *
 * <pre>
 *   class HmacKey {
 *      ...
 *      public byte[] getKeyMaterial(SecretKeyAccess access) {
 *        checkNotNull(access);
 *        return keyMaterial;
 *      }
 *   }
 * </pre>
 *
 * Users who want to call {@code getKeyMaterial} then need to get a {@code SecretKeyAccess} object
 * via {@code InsecureSecretKeyAccess.get()}.
 */
@CheckReturnValue
@Alpha
@Immutable
public final class SecretKeyAccess {
  private SecretKeyAccess() {}

  private static final SecretKeyAccess INSTANCE = new SecretKeyAccess();

  /** Package visibility restricted for {@link InsecureSecretKeyAccess}. */
  static SecretKeyAccess instance() {
    return INSTANCE;
  }

  /** Throws an exception if the passed in SecretKeyAccess is null, otherwise returns it. */
  @CanIgnoreReturnValue
  public static SecretKeyAccess requireAccess(@Nullable SecretKeyAccess access)
      throws GeneralSecurityException {
    if (access == null) {
      throw new GeneralSecurityException("SecretKeyAccess is required");
    }
    return access;
  }
}
