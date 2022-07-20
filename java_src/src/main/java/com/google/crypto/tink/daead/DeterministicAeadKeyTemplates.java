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
 * Pre-generated {@code KeyTemplate} for {@code DeterministicAead} keys. One can use these templates
 * to generate new {@code Keyset} with {@code KeysetHandle}. To generate a new keyset that contains
 * a single {@code AesSivKey}, one can do:
 *
 * <pre>
 *   Config.register(DeterministicAeadConfig.TINK_1_1_0);
 *   KeysetHandle handle = KeysetHandle.generateNew(DeterministicAeadKeyTemplates.AES256_SIV);
 *   DeterministicAead daead = handle.getPrimitive(DeterministicAead.class);
 * </pre>
 *
 * @since 1.1.0
 * @deprecated use {@link com.google.crypto.tink.KeyTemplates#get}, e.g.,
 *     KeyTemplates.get("AES256_SIV")
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
        .setTypeUrl(new AesSivKeyManager().getKeyType())
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  private DeterministicAeadKeyTemplates() {}
}
