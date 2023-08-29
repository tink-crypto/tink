// Copyright 2021 Google LLC
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

package com.google.crypto.tink.hybrid.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeKeyFormat;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link HpkePrivateKeyManager}. */
@RunWith(Theories.class)
public final class HpkePrivateKeyManagerTest {
  private HpkePrivateKeyManager manager;
  private KeyTypeManager.KeyFactory<HpkeKeyFormat, HpkePrivateKey> factory;

  @BeforeClass
  public static void setUpClass() throws Exception {
    HybridConfig.register();
  }

  @Before
  public void setUp() throws Exception {
    manager = new HpkePrivateKeyManager();
    factory = manager.keyFactory();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.HpkePrivateKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  private static HpkeKeyFormat createKeyFormat(HpkeKem kem, HpkeKdf kdf, HpkeAead aead) {
    HpkeParams params = HpkeParams.newBuilder().setKem(kem).setKdf(kdf).setAead(aead).build();
    return HpkeKeyFormat.newBuilder().setParams(params).build();
  }

  @DataPoints("validKeyFormats")
  public static final HpkeKeyFormat[] KEY_FORMATS =
      new HpkeKeyFormat[] {
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM),
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_256_GCM),
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.CHACHA20_POLY1305),
        createKeyFormat(HpkeKem.DHKEM_P256_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM),
        createKeyFormat(HpkeKem.DHKEM_P256_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_256_GCM),
        createKeyFormat(HpkeKem.DHKEM_P384_HKDF_SHA384, HpkeKdf.HKDF_SHA384, HpkeAead.AES_128_GCM),
        createKeyFormat(HpkeKem.DHKEM_P384_HKDF_SHA384, HpkeKdf.HKDF_SHA384, HpkeAead.AES_256_GCM),
        createKeyFormat(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeKdf.HKDF_SHA512, HpkeAead.AES_128_GCM),
        createKeyFormat(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeKdf.HKDF_SHA512, HpkeAead.AES_256_GCM),
      };

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW",
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM",
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_128_GCM_RAW",
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM",
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM_RAW",
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM",
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM_RAW",
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM",
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_256_GCM_RAW",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    if (TestUtil.isTsan()) {
      // key generation is too slow in Tsan.
      return;
    }
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void validateKeyFormat_failsWithMissingParams() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(HpkeKeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_failsWithInvalidKem() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(HpkeKem.KEM_UNKNOWN, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM);

    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  @Test
  public void validateKeyFormat_failsWithInvalidKdf() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.KDF_UNKNOWN, HpkeAead.AES_128_GCM);

    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  @Test
  public void validateKeyFormat_failsWithInvalidAead() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AEAD_UNKNOWN);

    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  @Theory
  public void createKey_succeeds(@FromDataPoints("validKeyFormats") HpkeKeyFormat keyFormat)
      throws Exception {
    if (TestUtil.isTsan()) {
      // key generation is too slow in Tsan.
      return;
    }
    HpkePrivateKey key = factory.createKey(keyFormat);

    assertThat(key.getVersion()).isEqualTo(manager.getVersion());
    assertThat(key.getPublicKey().getParams()).isEqualTo(keyFormat.getParams());
    assertThat(key.getPublicKey().getPublicKey()).isNotEmpty();
    assertThat(key.getPublicKey().getPublicKey().toByteArray().length)
        .isEqualTo(HpkeUtil.getEncodedPublicKeyLength(keyFormat.getParams().getKem()));
    assertThat(key.getPrivateKey()).isNotEmpty();
    assertThat(key.getPrivateKey().toByteArray().length)
        .isEqualTo(HpkeUtil.getEncodedPrivateKeyLength(keyFormat.getParams().getKem()));
  }

  @Theory
  public void validateKey_succeeds(@FromDataPoints("validKeyFormats") HpkeKeyFormat keyFormat)
      throws Exception {
    if (TestUtil.isTsan()) {
      // key generation is too slow in Tsan.
      return;
    }
    manager.validateKey(factory.createKey(keyFormat));
  }

  @Test
  public void validateKey_failsWithInvalidVersion() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeKdf.HKDF_SHA512, HpkeAead.AES_128_GCM);
    HpkePrivateKey key = HpkePrivateKey.newBuilder(factory.createKey(format)).setVersion(1).build();

    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_failsWithMissingPublicKey() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeKdf.HKDF_SHA512, HpkeAead.AES_128_GCM);
    HpkePrivateKey key =
        HpkePrivateKey.newBuilder(factory.createKey(format)).clearPublicKey().build();

    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_failsWithEmptyPrivateKey() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeKdf.HKDF_SHA512, HpkeAead.AES_128_GCM);
    HpkePrivateKey key =
        HpkePrivateKey.newBuilder(factory.createKey(format)).clearPrivateKey().build();

    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void getPublicKey() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(HpkeKem.DHKEM_P521_HKDF_SHA512, HpkeKdf.HKDF_SHA512, HpkeAead.AES_128_GCM);
    HpkePrivateKey key = factory.createKey(format);

    assertThat(manager.getPublicKey(key)).isEqualTo(key.getPublicKey());
  }

  @Theory
  public void parseKey(@FromDataPoints("validKeyFormats") HpkeKeyFormat keyFormat)
      throws Exception {
    HpkePrivateKey privateKey = factory.createKey(keyFormat);
    assertThat(manager.parseKey(privateKey.toByteString())).isEqualTo(privateKey);
  }

  @Theory
  public void parseKeyFormat(@FromDataPoints("validKeyFormats") HpkeKeyFormat keyFormat)
      throws Exception {
    assertThat(factory.parseKeyFormat(keyFormat.toByteString())).isEqualTo(keyFormat);
  }

  @Theory
  public void createPrimitive(@FromDataPoints("validKeyFormats") HpkeKeyFormat keyFormat)
      throws Exception {
    if (TestUtil.isTsan()) {
      // key generation is too slow in Tsan.
      return;
    }
    HpkePrivateKey privateKey = factory.createKey(keyFormat);
    HpkePublicKey publicKey = manager.getPublicKey(privateKey);
    HybridDecrypt hybridDecrypt = manager.getPrimitive(privateKey, HybridDecrypt.class);
    HybridEncrypt hybridEncrypt = HpkeEncrypt.createHpkeEncrypt(publicKey);

    byte[] input = Random.randBytes(200);
    byte[] contextInfo = Random.randBytes(100);
    byte[] ciphertext = hybridEncrypt.encrypt(input, contextInfo);
    byte[] plaintext = hybridDecrypt.decrypt(ciphertext, contextInfo);

    assertThat(plaintext).isEqualTo(input);
  }

  @Test
  public void registerPair() throws Exception {
    if (TestUtil.isTsan()) {
      // key generation is too slow in Tsan.
      return;
    }

    KeysetHandle privateHandle =
        KeysetHandle.generateNew(
            KeyTemplates.get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM"));
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    assertNotNull(privateHandle.getPrimitive(HybridDecrypt.class));
    assertNotNull(publicHandle.getPrimitive(HybridEncrypt.class));
  }
}
