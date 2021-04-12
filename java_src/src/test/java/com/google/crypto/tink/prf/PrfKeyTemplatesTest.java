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

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests forPrfKeyTemplates */
@RunWith(JUnit4.class)
public final class PrfKeyTemplatesTest {
  @Test
  public void testHKDF_SHA256() throws Exception {
    assertThat(PrfKeyTemplates.HKDF_SHA256.getTypeUrl())
        .isEqualTo(new HkdfPrfKeyManager().getKeyType());
    assertThat(PrfKeyTemplates.HKDF_SHA256.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
  }

  @Test
  public void testHKDF_SHA256_worksWithKeyManager() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.parseFrom(
            PrfKeyTemplates.HKDF_SHA256.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    new HkdfPrfKeyManager().keyFactory().validateKeyFormat(format);
  }

  @Test
  public void testHKDF_SHA256_values() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.parseFrom(
            PrfKeyTemplates.HKDF_SHA256.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA256);
  }
}
