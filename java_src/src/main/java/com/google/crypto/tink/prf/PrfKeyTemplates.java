// Copyright 2020 Google LLC
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

import com.google.crypto.tink.proto.AesCmacPrfKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.HmacPrfKeyFormat;
import com.google.crypto.tink.proto.HmacPrfParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;

/**
 * Key templates for PRF-Keys.
 *
 * @deprecated use {@link com.google.crypto.tink.KeyTemplates#get}, e.g.,
 *     KeyTemplates.get("HKDF_SHA256")
 */
@Deprecated
public final class PrfKeyTemplates {

  private PrfKeyTemplates() {}

  private static KeyTemplate createHkdfKeyTemplate() {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32) // the size in bytes of the HKDF key
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }

  private static KeyTemplate createHmacTemplate(int keySize, HashType hashType) {
    HmacPrfParams params = HmacPrfParams.newBuilder().setHash(hashType).build();
    HmacPrfKeyFormat format =
        HmacPrfKeyFormat.newBuilder().setParams(params).setKeySize(keySize).build();
    return KeyTemplate.newBuilder()
        .setTypeUrl(new HmacPrfKeyManager().getKeyType())
        .setValue(format.toByteString())
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }

  private static KeyTemplate createAes256CmacTemplate() {
    AesCmacPrfKeyFormat format = AesCmacPrfKeyFormat.newBuilder().setKeySize(32).build();
    return KeyTemplate.newBuilder()
        .setTypeUrl(new AesCmacPrfKeyManager().getKeyType())
        .setValue(format.toByteString())
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

  public static final KeyTemplate HMAC_SHA256_PRF = createHmacTemplate(32, HashType.SHA256);
  public static final KeyTemplate HMAC_SHA512_PRF = createHmacTemplate(64, HashType.SHA512);
  public static final KeyTemplate AES_CMAC_PRF = createAes256CmacTemplate();
}
