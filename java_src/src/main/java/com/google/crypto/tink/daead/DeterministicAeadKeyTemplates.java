// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;

/**
 * Pre-generated {@code KeyTemplate} for {@code DeterministicAead} keys.
 *
 * <p>We recommend to avoid this class in order to keep dependencies small.
 *
 * <ul>
 *   <li>Using this class adds a dependency on protobuf. We hope that eventually it is possible to
 *       use Tink without a dependency on protobuf.
 *   <li>Using this class adds a dependency on classes for all involved key types.
 * </ul>
 *
 * These dependencies all come from static class member variables, which are initialized when the
 * class is loaded. This implies that static analysis and code minimization tools (such as proguard)
 * cannot remove the usages either.
 *
 * <p>Instead, we recommend to use {@code KeysetHandle.generateEntryFromParametersName} or {@code
 * KeysetHandle.generateEntryFromParameters}.
 *
 * <p>One can use these templates to generate new {@code Keyset} with {@code KeysetHandle}. To
 * generate a new keyset that contains a single {@code AesSivKey}, one can do:
 *
 * <pre>
 *   DeterministicAeadConfig.register();
 *   KeysetHandle handle = KeysetHandle.generateNew(DeterministicAeadKeyTemplates.AES256_SIV);
 *   DeterministicAead daead = handle.getPrimitive(DeterministicAead.class);
 * </pre>
 *
 * @since 1.1.0
 * @deprecated Use {@link PredefinedDeterministicAeadParameters} instead.
 */
@Deprecated
public final class DeterministicAeadKeyTemplates {
  /** A {@code KeyTemplate} that generates new instances of {@code AesSivKey} with a 64-byte key. */
  public static final KeyTemplate AES256_SIV = createAesSivKeyTemplate(64);

  /**
   * @return a {@code KeyTemplate} containing a {@code AesSivKeyFormat} with some specified
   *     parameters.
   */
  public static KeyTemplate createAesSivKeyTemplate(int keySize) {
    AesSivKeyFormat format = AesSivKeyFormat.newBuilder().setKeySize(keySize).build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesSivKeyManager.getKeyType())
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  private DeterministicAeadKeyTemplates() {}
}
