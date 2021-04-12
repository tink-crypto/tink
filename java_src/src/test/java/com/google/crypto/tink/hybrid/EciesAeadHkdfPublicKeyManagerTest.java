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
package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadDemParams;
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey;
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey;
import com.google.crypto.tink.proto.EciesHkdfKemParams;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for RsaSsaPssVerifyKeyManager. */
@RunWith(JUnit4.class)
public final class EciesAeadHkdfPublicKeyManagerTest {
  private final EciesAeadHkdfPrivateKeyManager privateManager =
      new EciesAeadHkdfPrivateKeyManager();
  private final KeyTypeManager.KeyFactory<EciesAeadHkdfKeyFormat, EciesAeadHkdfPrivateKey> factory =
      privateManager.keyFactory();
  private final EciesAeadHkdfPublicKeyManager publicManager = new EciesAeadHkdfPublicKeyManager();

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(publicManager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey");
    assertThat(publicManager.getVersion()).isEqualTo(0);
    assertThat(publicManager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> publicManager.validateKey(EciesAeadHkdfPublicKey.getDefaultInstance()));
  }

  private EciesAeadHkdfKeyFormat createKeyFormat(
      EllipticCurveType curve,
      HashType hashType,
      EcPointFormat ecPointFormat,
      KeyTemplate demKeyTemplate,
      byte[] salt) {
    EciesHkdfKemParams kemParams =
        EciesHkdfKemParams.newBuilder()
            .setCurveType(curve)
            .setHkdfHashType(hashType)
            .setHkdfSalt(ByteString.copyFrom(salt))
            .build();
    EciesAeadDemParams demParams =
        EciesAeadDemParams.newBuilder().setAeadDem(demKeyTemplate).build();
    EciesAeadHkdfParams params =
        EciesAeadHkdfParams.newBuilder()
            .setKemParams(kemParams)
            .setDemParams(demParams)
            .setEcPointFormat(ecPointFormat)
            .build();

    return EciesAeadHkdfKeyFormat.newBuilder().setParams(params).build();
  }

  private EciesAeadHkdfPrivateKey createValidPrivateKey() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            "some salt".getBytes("UTF-8"));
    return factory.createKey(format);
  }

  @Test
  public void validateKey_valid() throws Exception {
    EciesAeadHkdfPrivateKey privateKey = createValidPrivateKey();
    publicManager.validateKey(privateManager.getPublicKey(privateKey));
  }

  @Test
  public void validateKey_invalidWrongVersion_throws() throws Exception {
    EciesAeadHkdfPrivateKey privateKey = createValidPrivateKey();
    EciesAeadHkdfPublicKey publicKey = privateManager.getPublicKey(privateKey);
    EciesAeadHkdfPublicKey invalidKey = EciesAeadHkdfPublicKey.newBuilder().setVersion(1).build();
    assertThrows(GeneralSecurityException.class, () -> publicManager.validateKey(invalidKey));
  }

  @Test
  public void validateKey_invalidPointFormat_throws() throws Exception {
    EciesAeadHkdfPrivateKey privateKey = createValidPrivateKey();
    EciesAeadHkdfPublicKey publicKey = privateManager.getPublicKey(privateKey);
    EciesAeadHkdfPublicKey invalidKey =
        EciesAeadHkdfPublicKey.newBuilder()
            .setParams(
                createKeyFormat(
                        EllipticCurveType.NIST_P256,
                        HashType.SHA256,
                        EcPointFormat.UNKNOWN_FORMAT,
                        AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
                        "some salt".getBytes("UTF-8"))
                    .getParams()).build();
    assertThrows(GeneralSecurityException.class, () -> publicManager.validateKey(invalidKey));
  }

  @Test
  public void createPrimitive() throws Exception {
    EciesAeadHkdfPrivateKey privateKey = createValidPrivateKey();
    HybridDecrypt hybridDecrypt = privateManager.getPrimitive(privateKey, HybridDecrypt.class);

    EciesAeadHkdfPublicKey publicKey = privateManager.getPublicKey(privateKey);
    HybridEncrypt hybridEncrypt = publicManager.getPrimitive(publicKey, HybridEncrypt.class);

    byte[] message = Random.randBytes(20);
    byte[] contextInfo = Random.randBytes(20);
    assertThat(hybridDecrypt.decrypt(hybridEncrypt.encrypt(message, contextInfo), contextInfo))
        .isEqualTo(message);
  }

}
