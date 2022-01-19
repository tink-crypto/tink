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

import com.google.crypto.tink.proto.AesCmacKeyFormat;
import com.google.crypto.tink.proto.AesCmacParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.Mac}.
 *
 * <p>One can use these templates to generate new {@link com.google.crypto.tink.proto.Keyset} with
 * {@link com.google.crypto.tink.KeysetHandle}. To generate a new keyset that contains a single
 * {@link com.google.crypto.tink.proto.HmacKey}, one can do:
 *
 * <pre>{@code
 * Config.register(Mac.TINK_1_0_0);
 * KeysetHandle handle = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
 * Mac mac = handle.getPrimitive(Mac.class);
 * }</pre>
 *
 * @since 1.0.0
 * @deprecated use {@link com.google.crypto.tink.KeyTemplates#get}, e.g.,
 *     KeyTemplates.get("HMAC_SHA256_128BITTAG")
 */
@Deprecated
public final class MacKeyTemplates {
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.HmacKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Tag size: 16 bytes
   *   <li>Hash function: SHA256
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final KeyTemplate HMAC_SHA256_128BITTAG =
      createHmacKeyTemplate(32, 16, HashType.SHA256);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.HmacKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Tag size: 32 bytes
   *   <li>Hash function: SHA256
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final KeyTemplate HMAC_SHA256_256BITTAG =
      createHmacKeyTemplate(32, 32, HashType.SHA256);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.HmacKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 64 bytes
   *   <li>Tag size: 32 bytes
   *   <li>Hash function: SHA512
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final KeyTemplate HMAC_SHA512_256BITTAG =
      createHmacKeyTemplate(64, 32, HashType.SHA512);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.HmacKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 64 bytes
   *   <li>Tag size: 64 bytes
   *   <li>Hash function: SHA512
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final KeyTemplate HMAC_SHA512_512BITTAG =
      createHmacKeyTemplate(64, 64, HashType.SHA512);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.CmacKey} with the following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Tag size: 16 bytes
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final KeyTemplate AES_CMAC =
      KeyTemplate.newBuilder()
          .setValue(
              AesCmacKeyFormat.newBuilder()
                  .setKeySize(32)
                  .setParams(AesCmacParams.newBuilder().setTagSize(16).build())
                  .build().toByteString())
          .setTypeUrl(new AesCmacKeyManager().getKeyType())
          .setOutputPrefixType(OutputPrefixType.TINK)
          .build();

  /**
   * @return a {@link KeyTemplate} containing a {@link HmacKeyFormat} with some specified
   *     parameters.
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
        .setTypeUrl(new HmacKeyManager().getKeyType())
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  private MacKeyTemplates() {}
}
