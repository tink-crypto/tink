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

package com.google.crypto.tink.prf;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Represents a key computing AES CMAC PRF.
 *
 * <p>This API is annotated with {@link com.google.crypto.tink.annotations.Alpha} because it is not
 * yet stable and might change in the future.
 */
@Alpha
@Immutable
public final class AesCmacPrfKey extends PrfKey {
  private final AesCmacPrfParameters parameters;
  private final SecretBytes keyBytes;

  private AesCmacPrfKey(AesCmacPrfParameters parameters, SecretBytes keyBytes) {
    this.parameters = parameters;
    this.keyBytes = keyBytes;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static AesCmacPrfKey create(AesCmacPrfParameters parameters, SecretBytes keyBytes)
      throws GeneralSecurityException {

    if (parameters.getKeySizeBytes() != keyBytes.size()) {
      throw new GeneralSecurityException("Key size mismatch");
    }
    return new AesCmacPrfKey(parameters, keyBytes);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getKeyBytes() {
    return keyBytes;
  }

  @Override
  public AesCmacPrfParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return null;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof AesCmacPrfKey)) {
      return false;
    }
    AesCmacPrfKey that = (AesCmacPrfKey) o;
    return that.parameters.equals(parameters) && that.keyBytes.equalsSecretBytes(keyBytes);
  }
}
