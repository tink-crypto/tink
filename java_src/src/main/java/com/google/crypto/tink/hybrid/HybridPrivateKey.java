// Copyright 2023 Google LLC
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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.PrivateKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import javax.annotation.Nullable;

/**
 * Representation of the decryption function for a hybrid encryption primitive.
 *
 * <p>The encryption function is available via {@link #getPublicKey}.
 */
@Immutable
public abstract class HybridPrivateKey extends Key implements PrivateKey {
  @Override
  public abstract HybridPublicKey getPublicKey();

  /**
   * Returns a {@link Bytes} instance, which is prefixed to every ciphertext.
   *
   * <p>Returns the same as {@code getPublicKey().getOutputPrefix()}.
   */
  public final Bytes getOutputPrefix() {
    return getPublicKey().getOutputPrefix();
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return getPublicKey().getIdRequirementOrNull();
  }

  @Override
  public HybridParameters getParameters() {
    return getPublicKey().getParameters();
  }
}
