// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal.testing;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class LegacyHybridDecryptKeyManagerTest {
  private static LegacyHybridDecryptKeyManager decryptKeyManager;
  private static LegacyHybridEncryptKeyManager encryptKeyManager;

  private static byte[] publicKeyByteArray;
  private static byte[] privateKeyByteArray;

  @BeforeClass
  public static void setUp() throws Exception {
    decryptKeyManager = new LegacyHybridDecryptKeyManager();
    encryptKeyManager = new LegacyHybridEncryptKeyManager();
    publicKeyByteArray =
        Hex.decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    privateKeyByteArray =
        Hex.decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
  }

  @Test
  public void testCreateHybridDecrypt_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.hybrid.HpkePublicKey publicKey =
        com.google.crypto.tink.hybrid.HpkePublicKey.create(
            parameters, Bytes.copyFrom(publicKeyByteArray), /* idRequirement= */ null);

    HpkeParams protoParams =
        HpkeParams.newBuilder()
            .setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256)
            .setKdf(HpkeKdf.HKDF_SHA256)
            .setAead(HpkeAead.AES_128_GCM)
            .build();
    HpkePublicKey protoPublicKey =
        HpkePublicKey.newBuilder()
            .setVersion(0)
            .setParams(protoParams)
            .setPublicKey(ByteString.copyFrom(publicKeyByteArray))
            .build();
    HpkePrivateKey protoPrivateKey =
        HpkePrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setPrivateKey(ByteString.copyFrom(privateKeyByteArray))
            .build();
    HybridDecrypt decrypt = decryptKeyManager.getPrimitive(protoPrivateKey.toByteString());

    HybridEncrypt encrypt = HpkeEncrypt.create(publicKey);

    byte[] plaintext = new byte[] {1, 2, 3, 4, 5};
    byte[] contextInfo = new byte[] {1};
    assertThat(decrypt.decrypt(encrypt.encrypt(plaintext, contextInfo), contextInfo))
        .isEqualTo(plaintext);
  }

  @Test
  public void testGetPublicKeyData_works() throws Exception {
    HpkeParams protoParams =
        HpkeParams.newBuilder()
            .setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256)
            .setKdf(HpkeKdf.HKDF_SHA256)
            .setAead(HpkeAead.AES_128_GCM)
            .build();
    HpkePublicKey protoPublicKey =
        HpkePublicKey.newBuilder()
            .setVersion(0)
            .setParams(protoParams)
            .setPublicKey(ByteString.copyFrom(publicKeyByteArray))
            .build();
    HpkePrivateKey protoPrivateKey =
        HpkePrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setPrivateKey(ByteString.copyFrom(privateKeyByteArray))
            .build();
    HybridDecrypt decrypt = decryptKeyManager.getPrimitive(protoPrivateKey.toByteString());

    KeyData keyData = decryptKeyManager.getPublicKeyData(protoPrivateKey.toByteString());
    HybridEncrypt encrypt = encryptKeyManager.getPrimitive(keyData.getValue());

    byte[] plaintext = new byte[] {1, 2, 3, 4, 5};
    byte[] contextInfo = new byte[] {1};
    assertThat(decrypt.decrypt(encrypt.encrypt(plaintext, contextInfo), contextInfo))
        .isEqualTo(plaintext);
  }
}
