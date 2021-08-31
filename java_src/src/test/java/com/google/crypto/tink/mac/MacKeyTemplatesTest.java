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

import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ExtensionRegistryLite;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for MacKeyTemplates. */
@RunWith(JUnit4.class)
public class MacKeyTemplatesTest {
  @Test
  public void hmacSha256_128BitTag() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    assertEquals(new HmacKeyManager().getKeyType(), template.getTypeUrl());
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
    assertEquals(new HmacKeyManager().getKeyType(), template.getTypeUrl());
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
    assertEquals(new HmacKeyManager().getKeyType(), template.getTypeUrl());
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
    assertEquals(new HmacKeyManager().getKeyType(), template.getTypeUrl());
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
    assertEquals(new HmacKeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());

    HmacKeyFormat format =
        HmacKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertEquals(keySize, format.getKeySize());
    assertEquals(tagSize, format.getParams().getTagSize());
    assertEquals(hashType, format.getParams().getHash());
  }
}
