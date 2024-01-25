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

package com.google.crypto.tink.streamingaead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.HashType;
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

/** Tests for StreamingAeadKeyTemplates. */
@RunWith(Theories.class)
public class StreamingAeadKeyTemplatesTest {
  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
  }

  @Test
  public void testAes128CtrHmacSha256_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_4KB;
    assertEquals(AesCtrHmacStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format =
        AesCtrHmacStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(16,              format.getKeySize());
    assertEquals(16,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
    assertEquals(HashType.SHA256, format.getParams().getHmacParams().getHash());
    assertEquals(32,              format.getParams().getHmacParams().getTagSize());
  }

  @Test
  public void testAes128CtrHmacSha256_1MB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_1MB;
    assertEquals(AesCtrHmacStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format =
        AesCtrHmacStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(16, format.getKeySize());
    assertEquals(16, format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(1048576, format.getParams().getCiphertextSegmentSize());
    assertEquals(HashType.SHA256, format.getParams().getHmacParams().getHash());
    assertEquals(32, format.getParams().getHmacParams().getTagSize());
  }

  @Test
  public void testAes256CtrHmacSha256_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_4KB;
    assertEquals(AesCtrHmacStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format =
        AesCtrHmacStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(32,              format.getKeySize());
    assertEquals(32,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
    assertEquals(HashType.SHA256, format.getParams().getHmacParams().getHash());
    assertEquals(32,              format.getParams().getHmacParams().getTagSize());
  }

  @Test
  public void testAes256CtrHmacSha256_1MB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_1MB;
    assertEquals(AesCtrHmacStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format =
        AesCtrHmacStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(32, format.getKeySize());
    assertEquals(32, format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(1048576, format.getParams().getCiphertextSegmentSize());
    assertEquals(HashType.SHA256, format.getParams().getHmacParams().getHash());
    assertEquals(32, format.getParams().getHmacParams().getTagSize());
  }

  @Test
  public void testAes128GcmHkdf_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB;
    assertEquals(AesGcmHkdfStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format =
        AesGcmHkdfStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(16,              format.getKeySize());
    assertEquals(16,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
  }

  @Test
  public void testAes128GcmHkdf_1MB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES128_GCM_HKDF_1MB;
    assertEquals(AesGcmHkdfStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format =
        AesGcmHkdfStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(16, format.getKeySize());
    assertEquals(16, format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(1048576, format.getParams().getCiphertextSegmentSize());
  }

  @Test
  public void testAes256GcmHkdf_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB;
    assertEquals(AesGcmHkdfStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format =
        AesGcmHkdfStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(32,              format.getKeySize());
    assertEquals(32,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
  }

  @Test
  public void testAes256GcmHkdf_1MB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES256_GCM_HKDF_1MB;
    assertEquals(AesGcmHkdfStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format =
        AesGcmHkdfStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(32,              format.getKeySize());
    assertEquals(32,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(1048576,         format.getParams().getCiphertextSegmentSize());
  }

  @Test
  public void testCreateAesCtrHmacStreamingKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    int mainKeySize = 42;
    int derivedKeySize = 24;
    int tagSize = 45;
    int ciphertextSegmentSize = 12345;
    HashType hkdfHashType = HashType.SHA512;
    HashType macHashType = HashType.UNKNOWN_HASH;
    KeyTemplate template = StreamingAeadKeyTemplates.createAesCtrHmacStreamingKeyTemplate(
        mainKeySize, hkdfHashType, derivedKeySize,
        macHashType, tagSize, ciphertextSegmentSize);
    assertEquals(AesCtrHmacStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format =
        AesCtrHmacStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(mainKeySize,           format.getKeySize());
    assertEquals(derivedKeySize,        format.getParams().getDerivedKeySize());
    assertEquals(hkdfHashType,          format.getParams().getHkdfHashType());
    assertEquals(ciphertextSegmentSize, format.getParams().getCiphertextSegmentSize());
    assertEquals(macHashType,           format.getParams().getHmacParams().getHash());
    assertEquals(tagSize,               format.getParams().getHmacParams().getTagSize());
  }

  @Test
  public void testCreateAesGcmHkdfStreamingKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    int mainKeySize = 42;
    int derivedKeySize = 24;
    int ciphertextSegmentSize = 12345;
    HashType hkdfHashType = HashType.SHA512;
    KeyTemplate template = StreamingAeadKeyTemplates.createAesGcmHkdfStreamingKeyTemplate(
        mainKeySize, hkdfHashType, derivedKeySize, ciphertextSegmentSize);
    assertEquals(AesGcmHkdfStreamingKeyManager.getKeyType(), template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format =
        AesGcmHkdfStreamingKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertEquals(mainKeySize,           format.getKeySize());
    assertEquals(derivedKeySize,        format.getParams().getDerivedKeySize());
    assertEquals(hkdfHashType,          format.getParams().getHkdfHashType());
    assertEquals(ciphertextSegmentSize, format.getParams().getCiphertextSegmentSize());
  }

  public static class Pair {
    public Pair(KeyTemplate template, StreamingAeadParameters parameters) {
      this.template = template;
      this.parameters = parameters;
    }

    KeyTemplate template;
    StreamingAeadParameters parameters;
  }

  @DataPoints("EquivalentPairs")
  public static final Pair[] TEMPLATES =
      new Pair[] {
        new Pair(
            StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_4KB,
            PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_4KB),
        new Pair(
            StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_1MB,
            PredefinedStreamingAeadParameters.AES128_CTR_HMAC_SHA256_1MB),
        new Pair(
            StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_4KB,
            PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_4KB),
        new Pair(
            StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_1MB,
            PredefinedStreamingAeadParameters.AES256_CTR_HMAC_SHA256_1MB),
        new Pair(
            StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB,
            PredefinedStreamingAeadParameters.AES128_GCM_HKDF_4KB),
        new Pair(
            StreamingAeadKeyTemplates.AES128_GCM_HKDF_1MB,
            PredefinedStreamingAeadParameters.AES128_GCM_HKDF_1MB),
        new Pair(
            StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB,
            PredefinedStreamingAeadParameters.AES256_GCM_HKDF_4KB),
        new Pair(
            StreamingAeadKeyTemplates.AES256_GCM_HKDF_1MB,
            PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB)
      };

  @Theory
  public void testParametersEqualsKeyTemplate(@FromDataPoints("EquivalentPairs") Pair p)
      throws Exception {
    assertThat(TinkProtoParametersFormat.parse(p.template.toByteArray())).isEqualTo(p.parameters);
  }
}
