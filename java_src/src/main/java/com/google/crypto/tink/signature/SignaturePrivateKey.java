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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.PrivateKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import javax.annotation.Nullable;

/**
 * A {@link SignaturePrivateKey} represents a digital signature primitive, which consists of a sign
 * and a verify function.
 *
 * <p>The verify function is only available indirectly, with {@link #getPublicKey}.
 */
@Immutable
public abstract class SignaturePrivateKey extends Key implements PrivateKey {
  /**
   * Returns the {@link SignaturePublicKey}, which contains the verify function of the digital
   * signature primitive.
   */
  @Override
  public abstract SignaturePublicKey getPublicKey();

  /**
   * Returns a {@link Bytes} instance which is prefixed to every signature.
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

  /**
   * Returns the parameters of this key.
   *
   * <p>Returns the same as {@code getPublicKey().getParameters()}.
   */
  @Override
  public SignatureParameters getParameters() {
    return getPublicKey().getParameters();
  }
}
