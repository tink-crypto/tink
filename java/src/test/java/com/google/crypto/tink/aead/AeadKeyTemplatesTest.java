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

package com.google.crypto.tink.aead;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AeadKeyTemplates. */
@RunWith(JUnit4.class)
public class AeadKeyTemplatesTest {
  @Test
  public void testAES128_GCM() throws Exception {
    KeyTemplate template = AeadKeyTemplates.AES128_GCM;
    assertEquals(AesGcmKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    AesGcmKeyFormat format = AesGcmKeyFormat.parseFrom(template.getValue());
    assertEquals(16, format.getKeySize());
  }

  @Test
  public void testAES256_GCM() throws Exception {
    KeyTemplate template = AeadKeyTemplates.AES256_GCM;
    assertEquals(AesGcmKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    AesGcmKeyFormat format = AesGcmKeyFormat.parseFrom(template.getValue());
    assertEquals(32, format.getKeySize());
  }

  @Test
  public void testCreateAesGcmKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    int keySize = 42;
    KeyTemplate template = AeadKeyTemplates.createAesGcmKeyTemplate(keySize);
    assertEquals(AesGcmKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());

    AesGcmKeyFormat format = AesGcmKeyFormat.parseFrom(template.getValue());
    assertEquals(keySize, format.getKeySize());
  }

  @Test
  public void testAES128_EAX() throws Exception {
    KeyTemplate template = AeadKeyTemplates.AES128_EAX;
    assertEquals(AesEaxKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    AesEaxKeyFormat format = AesEaxKeyFormat.parseFrom(template.getValue());
    assertEquals(16, format.getKeySize());
    assertTrue(format.hasParams());
    assertEquals(16, format.getParams().getIvSize());
  }

  @Test
  public void testAES256_EAX() throws Exception {
    KeyTemplate template = AeadKeyTemplates.AES256_EAX;
    assertEquals(AesEaxKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    AesEaxKeyFormat format = AesEaxKeyFormat.parseFrom(template.getValue());
    assertEquals(32, format.getKeySize());
    assertTrue(format.hasParams());
    assertEquals(16, format.getParams().getIvSize());
  }

  @Test
  public void testCreateAesEaxKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    int keySize = 42;
    int ivSize = 72;
    KeyTemplate template = AeadKeyTemplates.createAesEaxKeyTemplate(keySize, ivSize);
    assertEquals(AesEaxKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());

    AesEaxKeyFormat format = AesEaxKeyFormat.parseFrom(template.getValue());
    assertEquals(keySize, format.getKeySize());
    assertTrue(format.hasParams());
    assertEquals(ivSize, format.getParams().getIvSize());
  }

  @Test
  public void testAES128_CTR_HMAC_SHA256() throws Exception {
    KeyTemplate template = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    assertEquals(AesCtrHmacAeadKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasAesCtrKeyFormat());
    assertTrue(format.getAesCtrKeyFormat().hasParams());
    assertEquals(16, format.getAesCtrKeyFormat().getKeySize());
    assertEquals(16, format.getAesCtrKeyFormat().getParams().getIvSize());

    assertTrue(format.hasHmacKeyFormat());
    assertTrue(format.getHmacKeyFormat().hasParams());
    assertEquals(32, format.getHmacKeyFormat().getKeySize());
    assertEquals(16, format.getHmacKeyFormat().getParams().getTagSize());
    assertEquals(HashType.SHA256, format.getHmacKeyFormat().getParams().getHash());
  }

  @Test
  public void testAES256_CTR_HMAC_SHA256() throws Exception {
    KeyTemplate template = AeadKeyTemplates.AES256_CTR_HMAC_SHA256;
    assertEquals(AesCtrHmacAeadKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasAesCtrKeyFormat());
    assertTrue(format.getAesCtrKeyFormat().hasParams());
    assertEquals(32, format.getAesCtrKeyFormat().getKeySize());
    assertEquals(16, format.getAesCtrKeyFormat().getParams().getIvSize());

    assertTrue(format.hasHmacKeyFormat());
    assertTrue(format.getHmacKeyFormat().hasParams());
    assertEquals(32, format.getHmacKeyFormat().getKeySize());
    assertEquals(32, format.getHmacKeyFormat().getParams().getTagSize());
    assertEquals(HashType.SHA256, format.getHmacKeyFormat().getParams().getHash());
  }

  @Test
  public void testCreateAesCtrHmacAeadKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    int aesKeySize = 42;
    int ivSize = 72;
    int hmacKeySize = 24;
    int tagSize = 27;
    HashType hashType = HashType.UNKNOWN_HASH;
    KeyTemplate template = AeadKeyTemplates.createAesCtrHmacAeadKeyTemplate(
        aesKeySize, ivSize, hmacKeySize, tagSize, hashType);
    assertEquals(AesCtrHmacAeadKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.parseFrom(template.getValue());

    assertTrue(format.hasAesCtrKeyFormat());
    assertTrue(format.getAesCtrKeyFormat().hasParams());
    assertEquals(aesKeySize, format.getAesCtrKeyFormat().getKeySize());
    assertEquals(ivSize, format.getAesCtrKeyFormat().getParams().getIvSize());

    assertTrue(format.hasHmacKeyFormat());
    assertTrue(format.getHmacKeyFormat().hasParams());
    assertEquals(hmacKeySize, format.getHmacKeyFormat().getKeySize());
    assertEquals(tagSize, format.getHmacKeyFormat().getParams().getTagSize());
    assertEquals(hashType, format.getHmacKeyFormat().getParams().getHash());
  }

  @Test
  public void testCHACHA20_POLY1305() throws Exception {
    KeyTemplate template = AeadKeyTemplates.CHACHA20_POLY1305;
    assertEquals(ChaCha20Poly1305KeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    assertTrue(template.getValue().isEmpty());  // Empty format.
  }

  @Test
  public void testXCHACHA20_POLY1305() throws Exception {
    KeyTemplate template = AeadKeyTemplates.XCHACHA20_POLY1305;
    assertEquals(XChaCha20Poly1305KeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());
    assertTrue(template.getValue().isEmpty()); // Empty format.
  }

  @Test
  public void testCreateKmsAeadKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    String keyUri = "some example URI";
    KeyTemplate template = AeadKeyTemplates.createKmsAeadKeyTemplate(keyUri);
    assertEquals(KmsAeadKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());

    KmsAeadKeyFormat format = KmsAeadKeyFormat.parseFrom(template.getValue());
    assertEquals(keyUri, format.getKeyUri());
  }

  @Test
  public void testCreateKmsEnvelopeAeadKeyFormat() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    String kekUri = "some example KEK URI";
    KeyTemplate dekTemplate = AeadKeyTemplates.AES256_GCM;
    KeyTemplate template = AeadKeyTemplates.createKmsEnvelopeAeadKeyTemplate(kekUri, dekTemplate);
    assertEquals(KmsEnvelopeAeadKeyManager.TYPE_URL, template.getTypeUrl());
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType());

    KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.parseFrom(template.getValue());
    assertEquals(kekUri, format.getKekUri());
    assertEquals(dekTemplate.toString(), format.getDekTemplate().toString());
  }
}
