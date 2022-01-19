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
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Optional;

/** The implementation of {@code PrimitiveWrapper<JwtPublicKeyVerify>}. */
class JwtPublicKeyVerifyWrapper
    implements PrimitiveWrapper<JwtPublicKeyVerifyInternal, JwtPublicKeyVerify> {

  private static void validate(PrimitiveSet<JwtPublicKeyVerifyInternal> primitiveSet)
      throws GeneralSecurityException {
    for (List<PrimitiveSet.Entry<JwtPublicKeyVerifyInternal>> entries : primitiveSet.getAll()) {
      for (PrimitiveSet.Entry<JwtPublicKeyVerifyInternal> entry : entries) {
        if ((entry.getOutputPrefixType() != OutputPrefixType.RAW)
            && (entry.getOutputPrefixType() != OutputPrefixType.TINK)) {
          throw new GeneralSecurityException("unsupported OutputPrefixType");
        }
      }
    }
  }

  @Immutable
  private static class WrappedJwtPublicKeyVerify implements JwtPublicKeyVerify {

    @SuppressWarnings("Immutable")
    private final PrimitiveSet<JwtPublicKeyVerifyInternal> primitives;

    public WrappedJwtPublicKeyVerify(PrimitiveSet<JwtPublicKeyVerifyInternal> primitives) {
      this.primitives = primitives;
    }

    @Override
    public VerifiedJwt verifyAndDecode(String compact, JwtValidator validator)
        throws GeneralSecurityException {
      GeneralSecurityException interestingException = null;
      for (List<PrimitiveSet.Entry<JwtPublicKeyVerifyInternal>> entries : primitives.getAll()) {
        for (PrimitiveSet.Entry<JwtPublicKeyVerifyInternal> entry : entries) {
          try {
            Optional<String> kid = JwtFormat.getKid(entry.getKeyId(), entry.getOutputPrefixType());
            return entry.getPrimitive().verifyAndDecodeWithKid(compact, validator, kid);
          } catch (GeneralSecurityException e) {
            if (e instanceof JwtInvalidException) {
              // Keep this exception so that we are able to throw a meaningful message in the end
              interestingException = e;
            }
            // Ignored as we want to continue verification with other raw keys.
          }
        }
      }
      if (interestingException != null) {
        throw interestingException;
      }
      throw new GeneralSecurityException("invalid JWT");
    }
  }

  @Override
  public JwtPublicKeyVerify wrap(final PrimitiveSet<JwtPublicKeyVerifyInternal> primitives)
      throws GeneralSecurityException {
    validate(primitives);
    return new WrappedJwtPublicKeyVerify(primitives);
  }

  @Override
  public Class<JwtPublicKeyVerify> getPrimitiveClass() {
    return JwtPublicKeyVerify.class;
  }

  @Override
  public Class<JwtPublicKeyVerifyInternal> getInputPrimitiveClass() {
    return JwtPublicKeyVerifyInternal.class;
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link JwtPublicKeyVerify}
   * argument.
   */
  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new JwtPublicKeyVerifyWrapper());
  }
}
