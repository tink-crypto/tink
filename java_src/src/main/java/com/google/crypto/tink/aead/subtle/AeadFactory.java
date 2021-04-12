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

package com.google.crypto.tink.aead.subtle;

import com.google.crypto.tink.Aead;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/** Provides AEAD instances with a specific raw key. */
@Immutable
public interface AeadFactory {
  /** Returns the size of the AEAD key in bytes. */
  public int getKeySizeInBytes();

  /**
   * Creates a new {@code Aead}-primitive that uses the key material given in {@code symmetricKey},
   * which must be of length {@link #getKeySizeInBytes}.
   *
   * @return the newly created {@code Aead}-primitive.
   */
  public Aead createAead(final byte[] symmetricKey) throws GeneralSecurityException;
}
