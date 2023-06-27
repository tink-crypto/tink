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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.prf.PrfKey;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents a Derivation key which is based on a PRF.
 *
 * <p>An object of this class represents the map which 1) uses the given PRF (as specified by {@link
 * #getPrfKey}) to get sufficient key material from the salt, then 2) creates a key for the
 * parameters as specified in {@code getParameters().getDerivedKeyParameters()}.
 */
public final class PrfBasedKeyDerivationKey extends KeyDerivationKey {
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static PrfBasedKeyDerivationKey create(
      PrfBasedKeyDerivationParameters parameters, PrfKey prfKey, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!parameters.getPrfParameters().equals(prfKey.getParameters())) {
      throw new GeneralSecurityException(
          "PrfParameters of passed in PrfBasedKeyDerivationParameters and passed in prfKey"
              + " parameters object must match. DerivationParameters gave: "
              + parameters.getPrfParameters()
              + ", key gives: "
              + prfKey.getParameters());
    }
    if (parameters.getDerivedKeyParameters().hasIdRequirement()) {
      if (idRequirement == null) {
        throw new GeneralSecurityException(
            "Derived key has an ID requirement, but no idRequirement was passed in on creation of"
                + " this key");
      }
    }
    if (!parameters.getDerivedKeyParameters().hasIdRequirement()) {
      if (idRequirement != null) {
        throw new GeneralSecurityException(
            "Derived key has no ID requirement, but idRequirement was passed in on creation of"
                + " this key");
      }
    }
    return new PrfBasedKeyDerivationKey(parameters, prfKey, idRequirement);
  }

  private final PrfBasedKeyDerivationParameters parameters;
  private final PrfKey prfKey;
  private final Integer idRequirementOrNull;

  private PrfBasedKeyDerivationKey(
      PrfBasedKeyDerivationParameters parameters, PrfKey prfKey, @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.prfKey = prfKey;
    this.idRequirementOrNull = idRequirement;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public PrfKey getPrfKey() {
    return prfKey;
  }

  @Override
  public PrfBasedKeyDerivationParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirementOrNull;
  }

  @Override
  public boolean equalsKey(Key other) {
    if (!(other instanceof PrfBasedKeyDerivationKey)) {
      return false;
    }

    PrfBasedKeyDerivationKey otherKey = (PrfBasedKeyDerivationKey) other;
    return otherKey.getParameters().equals(getParameters())
        && otherKey.prfKey.equalsKey(prfKey)
        && Objects.equals(otherKey.idRequirementOrNull, idRequirementOrNull);
  }
}
