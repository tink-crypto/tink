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

package com.google.crypto.tink.aead;

import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.testing.Testdata;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests old (deprectated) and new AEAD KeyTemplates using Testdata.*/
@RunWith(JUnit4.class)
public final class AeadKeyTemplatesTestdataTest {

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testAes128Gcm() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "AES128_GCM");
    assertEquals(expectedTemplate, AeadKeyTemplates.AES128_GCM);
    assertEquals(expectedTemplate,
        KeyTemplateProtoConverter.toProto(AesGcmKeyManager.aes128GcmTemplate()));
  }

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testAes256Gcm() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "AES256_GCM");
    assertEquals(expectedTemplate, AeadKeyTemplates.AES256_GCM);
    assertEquals(expectedTemplate,
        KeyTemplateProtoConverter.toProto(AesGcmKeyManager.aes256GcmTemplate()));
  }

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testAes128Eax() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "AES128_EAX");
    assertEquals(expectedTemplate, AeadKeyTemplates.AES128_EAX);
    assertEquals(
        expectedTemplate,
        KeyTemplateProtoConverter.toProto(AesEaxKeyManager.aes128EaxTemplate()));
  }

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testAes256Eax() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "AES256_EAX");
    assertEquals(expectedTemplate, AeadKeyTemplates.AES256_EAX);
    assertEquals(
        expectedTemplate,
        KeyTemplateProtoConverter.toProto(AesEaxKeyManager.aes256EaxTemplate()));
  }

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testAes128CtrHmacSha256() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "AES128_CTR_HMAC_SHA256");
    assertEquals(expectedTemplate, AeadKeyTemplates.AES128_CTR_HMAC_SHA256);
    assertEquals(
        expectedTemplate,
        KeyTemplateProtoConverter.toProto(AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template()));
  }

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testAes256CtrHmacSha256() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "AES256_CTR_HMAC_SHA256");
    assertEquals(expectedTemplate, AeadKeyTemplates.AES256_CTR_HMAC_SHA256);
    assertEquals(
        expectedTemplate,
        KeyTemplateProtoConverter.toProto(AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template()));
  }

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testChaCha20Poly1305() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "CHACHA20_POLY1305");
    assertEquals(expectedTemplate, AeadKeyTemplates.CHACHA20_POLY1305);
    assertEquals(
        expectedTemplate,
        KeyTemplateProtoConverter.toProto(ChaCha20Poly1305KeyManager.chaCha20Poly1305Template()));
  }

  @Test
  @SuppressWarnings("deprecation")  // AeadKeyTemplates is deprecated, but we still want to test it.
  public void testXChaCha20Poly1305() throws Exception {
    KeyTemplate expectedTemplate = Testdata.getKeyTemplateProto("aead", "XCHACHA20_POLY1305");
    assertEquals(expectedTemplate, AeadKeyTemplates.XCHACHA20_POLY1305);
    assertEquals(
        expectedTemplate,
        KeyTemplateProtoConverter.toProto(XChaCha20Poly1305KeyManager.xChaCha20Poly1305Template()));
  }
}
