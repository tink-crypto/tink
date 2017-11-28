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

import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for StreamingAeadKeyTemplates. */
@RunWith(JUnit4.class)
public class StreamingAeadKeyTemplatesTest {
  @Test
  public void testAES128_CTR_HMAC_SHA256_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_4KB;
    assertEquals(AesCtrHmacStreamingKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format = AesCtrHmacStreamingKeyFormat.parseFrom(
        template.getValue());

    assertEquals(16,              format.getKeySize());
    assertEquals(16,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
    assertEquals(HashType.SHA256, format.getParams().getHmacParams().getHash());
    assertEquals(32,              format.getParams().getHmacParams().getTagSize());
  }

  @Test
  public void testAES256_CTR_HMAC_SHA256_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_4KB;
    assertEquals(AesCtrHmacStreamingKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format = AesCtrHmacStreamingKeyFormat.parseFrom(
        template.getValue());

    assertEquals(32,              format.getKeySize());
    assertEquals(32,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
    assertEquals(HashType.SHA256, format.getParams().getHmacParams().getHash());
    assertEquals(32,              format.getParams().getHmacParams().getTagSize());
  }

  @Test
  public void testAES128_GCM_HKDF_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB;
    assertEquals(AesGcmHkdfStreamingKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format = AesGcmHkdfStreamingKeyFormat.parseFrom(
        template.getValue());

    assertEquals(16,              format.getKeySize());
    assertEquals(16,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
  }

  @Test
  public void testAES256_GCM_HKDF_4KB() throws Exception {
    KeyTemplate template = StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB;
    assertEquals(AesGcmHkdfStreamingKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format = AesGcmHkdfStreamingKeyFormat.parseFrom(
        template.getValue());

    assertEquals(32,              format.getKeySize());
    assertEquals(32,              format.getParams().getDerivedKeySize());
    assertEquals(HashType.SHA256, format.getParams().getHkdfHashType());
    assertEquals(4096,            format.getParams().getCiphertextSegmentSize());
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
    HashType macHashType = HashType.SHA224;
    KeyTemplate template = StreamingAeadKeyTemplates.createAesCtrHmacStreamingKeyTemplate(
        mainKeySize, hkdfHashType, derivedKeySize,
        macHashType, tagSize, ciphertextSegmentSize);
    assertEquals(AesCtrHmacStreamingKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesCtrHmacStreamingKeyFormat format = AesCtrHmacStreamingKeyFormat.parseFrom(
        template.getValue());

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
    assertEquals(AesGcmHkdfStreamingKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.RAW, template.getOutputPrefixType());
    AesGcmHkdfStreamingKeyFormat format = AesGcmHkdfStreamingKeyFormat.parseFrom(
        template.getValue());

    assertEquals(mainKeySize,           format.getKeySize());
    assertEquals(derivedKeySize,        format.getParams().getDerivedKeySize());
    assertEquals(hkdfHashType,          format.getParams().getHkdfHashType());
    assertEquals(ciphertextSegmentSize, format.getParams().getCiphertextSegmentSize());
  }
}
