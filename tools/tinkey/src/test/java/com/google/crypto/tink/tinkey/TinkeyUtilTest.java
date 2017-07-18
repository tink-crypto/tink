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

package com.google.crypto.tink.tinkey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesCtrHmacAeadKeyManager;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.hybrid.HybridDecryptConfig;
import com.google.crypto.tink.hybrid.HybridEncryptConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.signature.PublicKeySignConfig;
import com.google.crypto.tink.signature.PublicKeyVerifyConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code TinkeyUtil}.
 */
@RunWith(JUnit4.class)
public class TinkeyUtilTest {
  @Before
  public void setUp() throws Exception {
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();
    HybridDecryptConfig.registerStandardKeyTypes();
    HybridEncryptConfig.registerStandardKeyTypes();
    PublicKeySignConfig.registerStandardKeyTypes();
    PublicKeyVerifyConfig.registerStandardKeyTypes();
  }

  @Test
  public void testCreateKeyTemplate() throws Exception {
    String keyType = AesGcmKeyManager.TYPE_URL;
    String keyFormat = "key_size: 16";
    KeyTemplate keyTemplate = TinkeyUtil.createKeyTemplateFromText(keyType, keyFormat);
    AesGcmKey keyProto1 = (AesGcmKey) Registry.INSTANCE.newKey(keyTemplate);
    assertEquals(16, keyProto1.getKeyValue().size());

    keyType = AesCtrHmacAeadKeyManager.TYPE_URL;
    keyFormat = "aes_ctr_key_format {params { iv_size: 12}, key_size: 16}, "
        + "hmac_key_format {params {hash: SHA256, tag_size: 10}, key_size: 32}";
    keyTemplate = TinkeyUtil.createKeyTemplateFromText(keyType, keyFormat);
    AesCtrHmacAeadKey keyProto2 = (AesCtrHmacAeadKey) Registry.INSTANCE.newKey(keyTemplate);
    assertEquals(16, keyProto2.getAesCtrKey().getKeyValue().size());
    assertEquals(12, keyProto2.getAesCtrKey().getParams().getIvSize());
    assertEquals(32, keyProto2.getHmacKey().getKeyValue().size());
    assertEquals(10, keyProto2.getHmacKey().getParams().getTagSize());
  }

  @Test
  public void testCreateKeyTemplateInvalid() throws Exception {
    String keyType = AesGcmKeyManager.TYPE_URL;
    String keyFormat = "key_size: 17";
    try {
      KeyTemplate unused = TinkeyUtil.createKeyTemplateFromText(keyType, keyFormat);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      System.out.println(e);
      assertTrue(e.toString().contains("invalid type URL or key format"));
    }

    keyType = "AesGcm1";
    try {
      KeyTemplate unused = TinkeyUtil.createKeyTemplateFromText(keyType, keyFormat);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.toString().contains("invalid type URL or key format"));
    }
  }
}
