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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * The implementation of {@code PrimitiveWrapper<JwtPublicKeySign>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To sign a message, it
 * uses the primary key in the keyset, and prepends to the signature a certain prefix associated
 * with the primary key.
 */
class JwtPublicKeySignWrapper implements PrimitiveWrapper<JwtPublicKeySign, JwtPublicKeySign> {

  private static void validate(PrimitiveSet<JwtPublicKeySign> primitiveSet)
      throws GeneralSecurityException {
    if (primitiveSet.getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
    if (primitiveSet.getAll().size() != 1 || primitiveSet.getRawPrimitives().isEmpty()) {
      throw new GeneralSecurityException("All JWT PublicKeySign keys must be raw.");
    }
  }

  @Immutable
  private static class WrappedJwtPublicKeySign implements JwtPublicKeySign {

    @SuppressWarnings("Immutable")
    private final PrimitiveSet<JwtPublicKeySign> primitives;

    public WrappedJwtPublicKeySign(final PrimitiveSet<JwtPublicKeySign> primitives) {
      this.primitives = primitives;
    }

    @Override
    public String signAndEncode(RawJwt token) throws GeneralSecurityException {
      return primitives.getPrimary().getPrimitive().signAndEncode(token);
    }
  }

  JwtPublicKeySignWrapper() {}

  @Override
  public JwtPublicKeySign wrap(final PrimitiveSet<JwtPublicKeySign> primitives)
      throws GeneralSecurityException {
    validate(primitives);
    return new WrappedJwtPublicKeySign(primitives);
  }

  @Override
  public Class<JwtPublicKeySign> getPrimitiveClass() {
    return JwtPublicKeySign.class;
  }

  @Override
  public Class<JwtPublicKeySign> getInputPrimitiveClass() {
    return JwtPublicKeySign.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link JwtPublicKeySign}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new JwtPublicKeySignWrapper());
  }
}
