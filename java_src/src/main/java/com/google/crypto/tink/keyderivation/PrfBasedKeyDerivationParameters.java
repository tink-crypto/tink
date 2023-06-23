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

package com.google.crypto.tink.keyderivation;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.prf.PrfParameters;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/** Represents the parameters needed in a {@link PrfBasedKeyDerivationKey}. */
@Immutable
public final class PrfBasedKeyDerivationParameters extends KeyDerivationParameters {
  /** Builds a new PrfBasedKeyDerivationParameters instance. */
  public static class Builder {
    @Nullable private PrfParameters prfParameters = null;

    @Nullable private Parameters derivedKeyParameters = null;

    /** Sets the parameters of the PRF used to create randomness from the salt. */
    public Builder setPrfParameters(PrfParameters prfParameters) {
      this.prfParameters = prfParameters;
      return this;
    }

    /**
     * The parameters of the keys which are in the result keyset when the user calls {@code
     * KeysetDeriver.deriveKeyset()}.
     */
    public Builder setDerivedKeyParameters(Parameters derivedKeyParameters) {
      this.derivedKeyParameters = derivedKeyParameters;
      return this;
    }

    public PrfBasedKeyDerivationParameters build() throws GeneralSecurityException {
      if (prfParameters == null) {
        throw new GeneralSecurityException("PrfParameters must be set.");
      }
      if (derivedKeyParameters == null) {
        throw new GeneralSecurityException("DerivedKeyParameters must be set.");
      }
      return new PrfBasedKeyDerivationParameters(prfParameters, derivedKeyParameters);
    }
  }

  private final PrfParameters prfParameters;
  private final Parameters derivedKeyParameters;

  private PrfBasedKeyDerivationParameters(
      PrfParameters prfParameters, Parameters derivedKeyParameters) {
    this.prfParameters = prfParameters;
    this.derivedKeyParameters = derivedKeyParameters;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The parameters of the PRF used to create randomness from the salt. */
  public PrfParameters getPrfParameters() {
    return prfParameters;
  }

  /**
   * The parameters of the keys which are in the result keyset when the user calls {@code
   * KeysetDeriver.deriveKeyset()}.
   */
  @Override
  public Parameters getDerivedKeyParameters() {
    return derivedKeyParameters;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof PrfBasedKeyDerivationParameters)) {
      return false;
    }
    PrfBasedKeyDerivationParameters that = (PrfBasedKeyDerivationParameters) o;
    return that.getPrfParameters() == getPrfParameters()
        && that.getDerivedKeyParameters() == getDerivedKeyParameters();
  }

  @Override
  public int hashCode() {
    return Objects.hash(PrfBasedKeyDerivationParameters.class, prfParameters, derivedKeyParameters);
  }
}
