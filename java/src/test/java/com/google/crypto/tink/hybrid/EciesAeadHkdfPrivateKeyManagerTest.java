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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.TestUtil;
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
import com.google.crypto.tink.subtle.EciesAeadHkdfDemHelper;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridEncrypt;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for EciesAeadHkdfPrivateKeyManager. */
@RunWith(JUnit4.class)
public class EciesAeadHkdfPrivateKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  private final EciesAeadHkdfPrivateKeyManager manager = new EciesAeadHkdfPrivateKeyManager();
  private final EciesAeadHkdfPrivateKeyManager.KeyFactory<
          EciesAeadHkdfKeyFormat, EciesAeadHkdfPrivateKey>
      factory = manager.keyFactory();

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    try {
      factory.validateKeyFormat(EciesAeadHkdfKeyFormat.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  private static EciesAeadHkdfKeyFormat createKeyFormat(
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

  @Test
  public void validateKeyFormat_valid() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            TestUtil.hexDecode("aabbccddeeff"));
    factory.validateKeyFormat(format);
  }

  @Test
  public void validateKeyFormat_noPointFormat_throws() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNKNOWN_FORMAT,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            TestUtil.hexDecode("aabbccddeeff"));
    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_noDem_throws() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            KeyTemplate.getDefaultInstance(),
            TestUtil.hexDecode("aabbccddeeff"));
    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_noKemCurve_throws() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.UNKNOWN_CURVE,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            TestUtil.hexDecode("aabbccddeeff"));
    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_noKemHash_throws() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.NIST_P256,
            HashType.UNKNOWN_HASH,
            EcPointFormat.UNCOMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            TestUtil.hexDecode("aabbccddeeff"));
    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void createKey_checkValues() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            TestUtil.hexDecode("aabbccddeeff"));
    EciesAeadHkdfPrivateKey key = factory.createKey(format);
    assertThat(key.getPublicKey().getParams()).isEqualTo(format.getParams());
    assertThat(key.getPublicKey().getX()).isNotEmpty();
    assertThat(key.getPublicKey().getY()).isNotEmpty();
    assertThat(key.getKeyValue()).isNotEmpty();
  }

  private EciesAeadHkdfPrivateKey createValidKey() throws Exception {
    EciesAeadHkdfKeyFormat format =
        createKeyFormat(
            EllipticCurveType.NIST_P256,
            HashType.SHA256,
            EcPointFormat.UNCOMPRESSED,
            AeadKeyTemplates.AES128_CTR_HMAC_SHA256,
            TestUtil.hexDecode("aabbccddeeff"));
    return factory.createKey(format);
  }

  @Test
  public void validateKey_valid() throws Exception {
    manager.validateKey(createValidKey());
  }

  @Test
  public void validateKey_invalidVersion_throws() throws Exception {
    EciesAeadHkdfPrivateKey key =
        EciesAeadHkdfPrivateKey.newBuilder(createValidKey()).setVersion(1).build();
    try {
      manager.validateKey(key);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void getPublicKey_values() throws Exception {
    EciesAeadHkdfPrivateKey key = createValidKey();
    EciesAeadHkdfPublicKey publicKey = manager.getPublicKey(key);

    assertThat(publicKey).isEqualTo(key.getPublicKey());
  }

  @Test
  public void createPrimitive() throws Exception {
    EciesAeadHkdfPrivateKey key = createValidKey();
    HybridDecrypt hybridDecrypt = manager.getPrimitive(key, HybridDecrypt.class);

    EciesAeadHkdfParams eciesParams = key.getPublicKey().getParams();
    EciesHkdfKemParams kemParams = eciesParams.getKemParams();
    ECPublicKey recipientPublicKey =
        EllipticCurves.getEcPublicKey(
            HybridUtil.toCurveType(kemParams.getCurveType()),
            key.getPublicKey().getX().toByteArray(),
            key.getPublicKey().getY().toByteArray());
    EciesAeadHkdfDemHelper demHelper =
        new RegistryEciesAeadHkdfDemHelper(eciesParams.getDemParams().getAeadDem());
    HybridEncrypt hybridEncrypt = new EciesAeadHkdfHybridEncrypt(
        recipientPublicKey,
        kemParams.getHkdfSalt().toByteArray(),
        HybridUtil.toHmacAlgo(kemParams.getHkdfHashType()),
        HybridUtil.toPointFormatType(eciesParams.getEcPointFormat()),
        demHelper);

    byte[] message = Random.randBytes(20);
    byte[] contextInfo = Random.randBytes(20);
    assertThat(hybridDecrypt.decrypt(hybridEncrypt.encrypt(message, contextInfo), contextInfo))
        .isEqualTo(message);
  }


}
