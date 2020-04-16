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

import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;

/** Key templates for PRF-Keys. */
public class PrfKeyTemplates {

  private PrfKeyTemplates() {}

  private static KeyTemplate createHkdfKeyTemplate() {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }

  /**
   * Generates a {@link KeyTemplate} for a {@link com.google.crypto.tink.proto.HkdfPrfKey} key with
   * the following parameters.
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>HMAC key size: 32 bytes
   *   <li>Salt: empty
   * </ul>
   */
  public static final KeyTemplate HKDF_SHA256 = createHkdfKeyTemplate();
}
