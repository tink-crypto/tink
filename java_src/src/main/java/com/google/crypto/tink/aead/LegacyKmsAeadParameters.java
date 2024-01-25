// Copyright 2023 Google Inc.
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

package com.google.crypto.tink.aead;

import java.security.GeneralSecurityException;
import java.util.Objects;

/** Describes the parameters of an {@link KmsAeadKey} */
public final class LegacyKmsAeadParameters extends AeadParameters {

  private final String keyUri;

  private LegacyKmsAeadParameters(String keyUri) {
    this.keyUri = keyUri;
  }

  public static LegacyKmsAeadParameters create(String keyUri) throws GeneralSecurityException {
    return new LegacyKmsAeadParameters(keyUri);
  }

  public String keyUri() {
    return keyUri;
  }

  @Override
  public boolean hasIdRequirement() {
    return false;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof LegacyKmsAeadParameters)) {
      return false;
    }
    LegacyKmsAeadParameters that = (LegacyKmsAeadParameters) o;
    return that.keyUri.equals(keyUri);
  }

  @Override
  public int hashCode() {
    return Objects.hash(LegacyKmsAeadParameters.class, keyUri);
  }

  @Override
  public String toString() {
    return "LegacyKmsAead Parameters (keyUri: " + keyUri + ")";
  }
}
