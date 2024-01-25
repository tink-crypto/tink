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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.errorprone.annotations.RestrictedApi;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/** Stores methods to create {@link Key} objects from {@link Parameters} with fixed randomness. */
public final class MutableKeyDerivationRegistry {
  private final Map<Class<? extends Parameters>, InsecureKeyCreator<? extends Parameters>>
      creators = new HashMap<>();

  /** A class to create key objects from parameters with given randomness. */
  public static interface InsecureKeyCreator<ParametersT extends Parameters> {
    public Key createKeyFromRandomness(
        ParametersT parameters,
        InputStream inputStream,
        @Nullable Integer idRequirement,
        SecretKeyAccess access)
        throws GeneralSecurityException;
  }

  private static final MutableKeyDerivationRegistry globalInstance =
      new MutableKeyDerivationRegistry();

  public static MutableKeyDerivationRegistry globalInstance() {
    return globalInstance;
  }

  /**
   * Adds a new "InsecureKeyCreator" to the instance.
   *
   * <p>If a creator for this class has been added previously, the two instances have to be equal.
   * Otherwise, this method throws a {@code GeneralSecurityException}.
   */
  public synchronized <ParametersT extends Parameters> void add(
      InsecureKeyCreator<ParametersT> creator, Class<ParametersT> parametersClass)
      throws GeneralSecurityException {
    InsecureKeyCreator<?> existingCreator = creators.get(parametersClass);
    if (existingCreator != null) {
      if (!existingCreator.equals(creator)) {
        throw new GeneralSecurityException(
            "Different key creator for parameters class already inserted");
      }
    }
    creators.put(parametersClass, creator);
  }

  /**
   * Creates a {@link Key} from a given {@link Parameters} object and additional data.
   *
   * <p>Finds the previously added creator (with {@link #add}) for the class given by {@code
   * parameters.getClass()} and uses it.
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public Key createKeyFromRandomness(
      Parameters parameters,
      InputStream inputStream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return createKeyFromRandomnessTyped(parameters, inputStream, idRequirement, access);
  }

  // Separate function to hide use of generics in the above public function.
  private synchronized <ParametersT extends Parameters> Key createKeyFromRandomnessTyped(
      ParametersT parameters,
      InputStream inputStream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    Class<?> parametersClass = parameters.getClass();
    InsecureKeyCreator<?> creator = creators.get(parametersClass);
    if (creator == null) {
      throw new GeneralSecurityException(
          "Cannot use key derivation to derive key for parameters "
              + parameters
              + ": no key creator for this class was registered.");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    InsecureKeyCreator<ParametersT> castCreator = (InsecureKeyCreator<ParametersT>) creator;
    return castCreator.createKeyFromRandomness(parameters, inputStream, idRequirement, access);
  }
}
