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

import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests forPrfKeyTemplates */
@RunWith(Theories.class)
public final class PrfKeyTemplatesTest {
  @BeforeClass
  public static void setUp() throws Exception {
    PrfConfig.register();
  }

  @Test
  public void hkdfSha256() throws Exception {
    assertThat(PrfKeyTemplates.HKDF_SHA256.getTypeUrl())
        .isEqualTo(new HkdfPrfKeyManager().getKeyType());
    assertThat(PrfKeyTemplates.HKDF_SHA256.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
  }

  @Test
  public void hkdfSha256_worksWithKeyManager() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.parseFrom(
            PrfKeyTemplates.HKDF_SHA256.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    new HkdfPrfKeyManager().keyFactory().validateKeyFormat(format);
  }

  @Test
  public void hkdfSha256Values() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.parseFrom(
            PrfKeyTemplates.HKDF_SHA256.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(format.getKeySize()).isEqualTo(32);
    assertThat(format.getParams().getHash()).isEqualTo(HashType.SHA256);
  }

  public static class Pair {
    public Pair(KeyTemplate template, PrfParameters parameters) {
      this.template = template;
      this.parameters = parameters;
    }

    KeyTemplate template;
    PrfParameters parameters;
  }

  @DataPoints("EquivalentPairs")
  public static final Pair[] TEMPLATES =
      new Pair[] {
        new Pair(PrfKeyTemplates.HKDF_SHA256, PredefinedPrfParameters.HKDF_SHA256),
        new Pair(PrfKeyTemplates.HMAC_SHA256_PRF, PredefinedPrfParameters.HMAC_SHA256_PRF),
        new Pair(PrfKeyTemplates.HMAC_SHA512_PRF, PredefinedPrfParameters.HMAC_SHA512_PRF),
        new Pair(PrfKeyTemplates.AES_CMAC_PRF, PredefinedPrfParameters.AES_CMAC_PRF)
      };

  @Theory
  public void testParametersEqualsKeyTemplate(@FromDataPoints("EquivalentPairs") Pair p)
      throws Exception {
    assertThat(TinkProtoParametersFormat.parse(p.template.toByteArray())).isEqualTo(p.parameters);
  }
}
