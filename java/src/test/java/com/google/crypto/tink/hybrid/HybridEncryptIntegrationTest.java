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

package com.google.crypto.tink.hybrid;

import static org.junit.Assert.assertArrayEquals;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests which run the everything for the Hybrid primitives. */
@RunWith(JUnit4.class)
public class HybridEncryptIntegrationTest {
  @BeforeClass
  public static void setUp() throws Exception {
    HybridConfig.register();
  }

  @Test
  public void testBasicEncryption() throws Exception {
    EllipticCurveType curve = EllipticCurveType.NIST_P384;
    HashType hashType = HashType.SHA256;
    EcPointFormat primaryPointFormat = EcPointFormat.UNCOMPRESSED;
    EcPointFormat rawPointFormat = EcPointFormat.COMPRESSED;
    KeyTemplate primaryDemKeyTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;

    KeyTemplate rawDemKeyTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    byte[] primarySalt = "some salt".getBytes("UTF-8");
    byte[] rawSalt = "other salt".getBytes("UTF-8");

    EciesAeadHkdfPrivateKey primaryPrivProto =
        TestUtil.generateEciesAeadHkdfPrivKey(
            curve, hashType, primaryPointFormat, primaryDemKeyTemplate, primarySalt);

    Key primaryPriv =
        TestUtil.createKey(
            TestUtil.createKeyData(
                primaryPrivProto,
                EciesAeadHkdfPrivateKeyManager.TYPE_URL,
                KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
            8,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    Key primaryPub =
        TestUtil.createKey(
            TestUtil.createKeyData(
                primaryPrivProto.getPublicKey(),
                EciesAeadHkdfPublicKeyManager.TYPE_URL,
                KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);

    EciesAeadHkdfPrivateKey rawPrivProto =
        TestUtil.generateEciesAeadHkdfPrivKey(
            curve, hashType, rawPointFormat, rawDemKeyTemplate, rawSalt);

    Key rawPriv =
        TestUtil.createKey(
            TestUtil.createKeyData(
                rawPrivProto,
                EciesAeadHkdfPrivateKeyManager.TYPE_URL,
                KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE),
            11,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    Key rawPub =
        TestUtil.createKey(
            TestUtil.createKeyData(
                rawPrivProto.getPublicKey(),
                EciesAeadHkdfPublicKeyManager.TYPE_URL,
                KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC),
            43,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    KeysetHandle keysetHandlePub =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(primaryPub, rawPub));
    KeysetHandle keysetHandlePriv =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(primaryPriv, rawPriv));
    HybridEncrypt hybridEncrypt = keysetHandlePub.getPrimitive(HybridEncrypt.class);
    HybridDecrypt hybridDecrypt = keysetHandlePriv.getPrimitive(HybridDecrypt.class);
    byte[] plaintext = Random.randBytes(20);
    byte[] contextInfo = Random.randBytes(20);
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo);
    assertArrayEquals(plaintext, hybridDecrypt.decrypt(ciphertext, contextInfo));
  }
}
