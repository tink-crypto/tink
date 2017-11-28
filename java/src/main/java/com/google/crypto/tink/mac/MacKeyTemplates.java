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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;

/**
 * Pre-generated {@code KeyTemplate} for {@code Mac}. One can use these templates
 * to generate new {@code Keyset} with {@code KeysetHandle}. To generate a new keyset
 * that contains a single {@code HmacKey}, one can do:
 * <pre>
 *   Config.register(Mac.TINK_1_0_0);
 *   KeysetHandle handle = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
 *   Mac mac = MacFactory.getPrimitive(handle);
 * </pre>
 */
public final class MacKeyTemplates {
  /**
   * A {@code KeyTemplate} that generates new instances of {@code HmacKey} with the following
   * parameters:
   *   - Key size: 32 bytes
   *   - Tag size: 16 bytes
   *   - Hash function: SHA256
   */
  public static final KeyTemplate HMAC_SHA256_128BITTAG = createHmacKeyTemplate(
      32, 16, HashType.SHA256);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code HmacKey} with the following
   * parameters:
   *   - Key size: 32 bytes
   *   - Tag size: 32 bytes
   *   - Hash function: SHA256
   */
  public static final KeyTemplate HMAC_SHA256_256BITTAG = createHmacKeyTemplate(
      32, 32, HashType.SHA256);

  /**
   * @return a {@code KeyTemplate} containing a {@code HmacKeyFormat} with some specified
   * parameters.
   */
  public static KeyTemplate createHmacKeyTemplate(int keySize, int tagSize, HashType hashType) {
    HmacParams params = HmacParams.newBuilder()
        .setHash(hashType)
        .setTagSize(tagSize)
        .build();
    HmacKeyFormat format = HmacKeyFormat.newBuilder()
        .setParams(params)
        .setKeySize(keySize)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(HmacKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }
}
