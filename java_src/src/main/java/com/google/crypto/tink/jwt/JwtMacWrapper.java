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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Optional;

/**
 * JwtMacWrapper is the implementation of {@link PrimitiveWrapper} for the {@link JwtMac} primitive.
 */
class JwtMacWrapper implements PrimitiveWrapper<JwtMacInternal, JwtMac> {
  private static void validate(PrimitiveSet<JwtMacInternal> primitiveSet)
      throws GeneralSecurityException {
    if (primitiveSet.getPrimary() == null) {
      throw new GeneralSecurityException("Primitive set has no primary.");
    }
    for (List<PrimitiveSet.Entry<JwtMacInternal>> entries : primitiveSet.getAll()) {
      for (PrimitiveSet.Entry<JwtMacInternal> entry : entries) {
        if ((entry.getOutputPrefixType() != OutputPrefixType.RAW)
            && (entry.getOutputPrefixType() != OutputPrefixType.TINK)) {
          throw new GeneralSecurityException("unsupported OutputPrefixType");
        }
      }
    }
  }

  @Immutable
  private static class WrappedJwtMac implements JwtMac {
    @SuppressWarnings("Immutable") // We do not mutate the primitive set.
    private final PrimitiveSet<JwtMacInternal> primitives;

    private WrappedJwtMac(PrimitiveSet<JwtMacInternal> primitives) {
      this.primitives = primitives;
    }

    @Override
    public String computeMacAndEncode(RawJwt token) throws GeneralSecurityException {
      PrimitiveSet.Entry<JwtMacInternal> entry = primitives.getPrimary();
      Optional<String> kid = JwtFormat.getKid(entry.getKeyId(), entry.getOutputPrefixType());
      return entry.getPrimitive().computeMacAndEncodeWithKid(token, kid);
    }

    @Override
    public VerifiedJwt verifyMacAndDecode(String compact, JwtValidator validator)
        throws GeneralSecurityException {
      GeneralSecurityException interestingException = null;
      for (List<PrimitiveSet.Entry<JwtMacInternal>> entries : primitives.getAll()) {
        for (PrimitiveSet.Entry<JwtMacInternal> entry : entries) {
          try {
            Optional<String> kid = JwtFormat.getKid(entry.getKeyId(), entry.getOutputPrefixType());
            return entry.getPrimitive().verifyMacAndDecodeWithKid(compact, validator, kid);
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
      throw new GeneralSecurityException("invalid MAC");
    }
  }

  JwtMacWrapper() {}

  @Override
  public JwtMac wrap(final PrimitiveSet<JwtMacInternal> primitives)
      throws GeneralSecurityException {
    validate(primitives);
    return new WrappedJwtMac(primitives);
  }

  @Override
  public Class<JwtMac> getPrimitiveClass() {
    return JwtMac.class;
  }

  @Override
  public Class<JwtMacInternal> getInputPrimitiveClass() {
    return JwtMacInternal.class;
  }

 public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new JwtMacWrapper());
  }
}
