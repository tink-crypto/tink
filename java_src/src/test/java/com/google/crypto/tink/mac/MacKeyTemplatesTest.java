// Copyright 2017 Google LLC
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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
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

/** Tests for MacKeyTemplates. */
@RunWith(Theories.class)
public class MacKeyTemplatesTest {
  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
  }

  @Test
  public void hmacSha256_128BitTag() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    assertEquals(HmacKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(32, format.getKeySize());
    assertEquals(16, format.getParams().getTagSize());
    assertEquals(HashType.SHA256, format.getParams().getHash());
  }

  @Test
  public void hmacSha256_256BitTag() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_256BITTAG;
    assertEquals(HmacKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(32, format.getKeySize());
    assertEquals(32, format.getParams().getTagSize());
    assertEquals(HashType.SHA256, format.getParams().getHash());
  }

  @Test
  public void hmacSha512_256BitTag() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA512_256BITTAG;
    assertEquals(HmacKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(64, format.getKeySize());
    assertEquals(32, format.getParams().getTagSize());
    assertEquals(HashType.SHA512, format.getParams().getHash());
  }

  @Test
  public void hmacSha512_512BitTag() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA512_512BITTAG;
    assertEquals(HmacKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(64, format.getKeySize());
    assertEquals(64, format.getParams().getTagSize());
    assertEquals(HashType.SHA512, format.getParams().getHash());
  }

  @Test
  public void testCreateHmacKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    int keySize = 42;
    int tagSize = 24;
    HashType hashType = HashType.SHA512;
    KeyTemplate template = MacKeyTemplates.createHmacKeyTemplate(keySize, tagSize, hashType);
    assertEquals(HmacKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());

    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertEquals(keySize, format.getKeySize());
    assertEquals(tagSize, format.getParams().getTagSize());
    assertEquals(hashType, format.getParams().getHash());
  }

  public static class Pair {
    public Pair(KeyTemplate template, MacParameters parameters) {
      this.template = template;
      this.parameters = parameters;
    }

    KeyTemplate template;
    MacParameters parameters;
  }

  @DataPoints("EquivalentPairs")
  public static final Pair[] TEMPLATES =
      new Pair[] {
        new Pair(
            MacKeyTemplates.HMAC_SHA256_128BITTAG, PredefinedMacParameters.HMAC_SHA256_128BITTAG),
        new Pair(
            MacKeyTemplates.HMAC_SHA256_256BITTAG, PredefinedMacParameters.HMAC_SHA256_256BITTAG),
        new Pair(
            MacKeyTemplates.HMAC_SHA512_256BITTAG, PredefinedMacParameters.HMAC_SHA512_256BITTAG),
        new Pair(
            MacKeyTemplates.HMAC_SHA512_512BITTAG, PredefinedMacParameters.HMAC_SHA512_512BITTAG),
        new Pair(MacKeyTemplates.AES_CMAC, PredefinedMacParameters.AES_CMAC),
      };

  @Theory
  public void testParametersEqualsKeyTemplate(@FromDataPoints("EquivalentPairs") Pair p)
      throws Exception {
    assertThat(TinkProtoParametersFormat.parse(p.template.toByteArray())).isEqualTo(p.parameters);
  }
}
