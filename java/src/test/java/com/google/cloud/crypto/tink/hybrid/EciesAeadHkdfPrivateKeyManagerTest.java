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

package com.google.cloud.crypto.tink.hybrid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.google.cloud.crypto.tink.CommonProto.EcPointFormat;
import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.EciesAeadHkdfProto.EciesAeadHkdfKeyFormat;
import com.google.cloud.crypto.tink.EciesAeadHkdfProto.EciesAeadHkdfParams;
import com.google.cloud.crypto.tink.EciesAeadHkdfProto.EciesAeadHkdfPrivateKey;
import com.google.cloud.crypto.tink.HybridDecrypt;
import com.google.cloud.crypto.tink.HybridEncrypt;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.TestUtil;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.Random;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for EciesAeadHkdfPrivateKeyManager.
 */
@RunWith(JUnit4.class)
public class EciesAeadHkdfPrivateKeyManagerTest {
  private static final int AES_KEY_SIZE = 16;
  private static final int HMAC_KEY_SIZE = 20;

  @Before
  public void setUp() throws Exception {
    HybridEncryptFactory.registerStandardKeyTypes();
    HybridDecryptFactory.registerStandardKeyTypes();
  }

  @Test
  public void testNewKey() throws Exception {
    int ivSize = 12;
    int tagSize = 16;
    EllipticCurveType curve = EllipticCurveType.NIST_P384;
    HashType hashType = HashType.SHA256;
    EcPointFormat pointFormat = EcPointFormat.UNCOMPRESSED;
    KeyTemplate demKeyTemplate = TestUtil.createAesCtrHmacAeadKeyTemplate(AES_KEY_SIZE, ivSize,
        HMAC_KEY_SIZE, tagSize);
    byte[] salt = "some salt".getBytes("UTF-8");
    EciesAeadHkdfParams params = TestUtil.createEciesAeadHkdfParams(curve, hashType, pointFormat,
        demKeyTemplate, salt);

    EciesAeadHkdfPrivateKeyManager manager = new EciesAeadHkdfPrivateKeyManager();
    EciesAeadHkdfPrivateKey keyProto = manager.newKey(
        EciesAeadHkdfKeyFormat.newBuilder().setParams(params).build());
    assertEquals(params, keyProto.getPublicKey().getParams());

    Key primaryPriv = TestUtil.createKey(
        TestUtil.createKeyData(
            keyProto,
            "type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPrivateKey",
            KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
        8,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    Key primaryPub = TestUtil.createKey(
        TestUtil.createKeyData(
            keyProto.getPublicKey(),
            "type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPublicKey",
            KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    KeysetHandle keysetHandlePub = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primaryPub));
    KeysetHandle keysetHandlePriv = TestUtil.createKeysetHandle(
        TestUtil.createKeyset(primaryPriv));
    HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(keysetHandlePub);
    HybridDecrypt hybridDecrypt = HybridDecryptFactory.getPrimitive(keysetHandlePriv);
    byte[] plaintext = Random.randBytes(20);
    byte[] contextInfo = Random.randBytes(20);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo);
    assertArrayEquals(plaintext, hybridDecrypt.decrypt(ciphertext, contextInfo));
  }
}
