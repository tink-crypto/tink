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

package com.google.crypto.tink.daead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.DeterministicAead} keys.
 *
 * <p>Note: if you want to keep dependencies small, consider inlining the constants here.
 */
public final class PredefinedDeterministicAeadParameters {
  /** A {@code KeyTemplate} that generates new instances of {@code AesSivKey} with a 64-byte key. */
  public static final AesSivParameters AES256_SIV =
      exceptionIsBug(
          () ->
              AesSivParameters.builder()
                  .setKeySizeBytes(64)
                  .setVariant(AesSivParameters.Variant.TINK)
                  .build());

  private PredefinedDeterministicAeadParameters() {}
}
