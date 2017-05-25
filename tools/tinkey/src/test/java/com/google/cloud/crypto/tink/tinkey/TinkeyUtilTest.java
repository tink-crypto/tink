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

package com.google.cloud.crypto.tink.tinkey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKey;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKey;
import com.google.cloud.crypto.tink.CleartextKeysetHandle;
import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.EciesAeadHkdfProto.EciesAeadHkdfPrivateKey;
import com.google.cloud.crypto.tink.HybridDecrypt;
import com.google.cloud.crypto.tink.HybridEncrypt;
import com.google.cloud.crypto.tink.KeysetManager;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.aead.AesCtrHmacAeadKeyManager;
import com.google.cloud.crypto.tink.aead.AesGcmKeyManager;
import com.google.cloud.crypto.tink.hybrid.EciesAeadHkdfPublicKeyManager;
import com.google.cloud.crypto.tink.hybrid.HybridDecryptFactory;
import com.google.cloud.crypto.tink.hybrid.HybridEncryptFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.signature.PublicKeySignFactory;
import com.google.cloud.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.cloud.crypto.tink.subtle.Random;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for {@code TinkeyUtil}.
 */
@RunWith(JUnit4.class)
public class TinkeyUtilTest {
  private static final int AES_KEY_SIZE = 16;
  private static final int HMAC_KEY_SIZE = 20;

  @Before
  public void setUp() throws Exception {
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
    HybridDecryptFactory.registerStandardKeyTypes();
    HybridEncryptFactory.registerStandardKeyTypes();
    PublicKeySignFactory.registerStandardKeyTypes();
    PublicKeyVerifyFactory.registerStandardKeyTypes();
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

  /**
   * Tests a public keyset is extracted properly from a private keyset.
   * TODO(thaidn): move this to integration test?
   */
  @Test
  public void testExtractPublicKey() throws Exception {
    int ivSize = 12;
    int tagSize = 16;
    EllipticCurveType curve = EllipticCurveType.NIST_P256;
    HashType hashType = HashType.SHA256;
    EcPointFormat pointFormat = EcPointFormat.UNCOMPRESSED;
    KeyTemplate demKeyTemplate = TestUtil.createAesCtrHmacAeadKeyTemplate(AES_KEY_SIZE, ivSize,
        HMAC_KEY_SIZE, tagSize);
    byte[] salt = "some salt".getBytes("UTF-8");
    KeyTemplate keyTemplate = TestUtil.createEciesAeadHkdfKeyTemplate(curve, hashType, pointFormat,
        demKeyTemplate, salt);

    KeysetManager managerPrivate = new KeysetManager.Builder()
        .setKeyTemplate(keyTemplate)
        .build()
        .rotate();
    KeyData privateKeyData = managerPrivate.getKeysetHandle().getKeyset().getKey(0).getKeyData();
    EciesAeadHkdfPrivateKey privateKey = EciesAeadHkdfPrivateKey.parseFrom(
        privateKeyData.getValue());
    HybridDecrypt hybridDecrypt = HybridDecryptFactory.getPrimitive(
        managerPrivate.getKeysetHandle());

    Keyset publicKeyset = TinkeyUtil.createPublicKeyset(
        managerPrivate.getKeysetHandle().getKeyset());
    assertEquals(1, publicKeyset.getKeyCount());
    KeyData publicKeyData = publicKeyset.getKey(0).getKeyData();
    assertEquals(EciesAeadHkdfPublicKeyManager.TYPE_URL,
        publicKeyData.getTypeUrl());
    assertEquals(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC, publicKeyData.getKeyMaterialType());
    assertArrayEquals(privateKey.getPublicKey().toByteArray(),
        publicKeyData.getValue().toByteArray());

    HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(
        CleartextKeysetHandle.parseFrom(publicKeyset));
    byte[] plaintext = Random.randBytes(20);
    byte[] contextInfo = Random.randBytes(20);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo);
    assertArrayEquals(plaintext, hybridDecrypt.decrypt(ciphertext, contextInfo));
  }
}
