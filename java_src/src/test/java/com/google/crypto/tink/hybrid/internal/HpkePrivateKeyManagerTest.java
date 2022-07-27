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
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.Registry;
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
import java.security.GeneralSecurityException;
import org.junit.Before;
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

  @Before
  public void setUp() {
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

  @Test
  public void validateKeyFormat_succeeds() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM);

    factory.validateKeyFormat(format);
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
  public void keyFormats(@FromDataPoints("templateNames") String template) throws Exception {
    factory.validateKeyFormat(factory.keyFormats().get(template).keyFormat);
  }

  @Theory
  public void createKey_succeeds(@FromDataPoints("templateNames") String template)
      throws Exception {
    HpkeKeyFormat format = factory.keyFormats().get(template).keyFormat;
    HpkePrivateKey key = factory.createKey(format);

    assertThat(key.getVersion()).isEqualTo(manager.getVersion());
    assertThat(key.getPublicKey().getParams()).isEqualTo(format.getParams());
    assertThat(key.getPublicKey().getPublicKey()).isNotEmpty();
    assertThat(key.getPrivateKey()).isNotEmpty();
  }

  @Theory
  public void validateKey_succeeds(@FromDataPoints("templateNames") String template)
      throws Exception {
    HpkeKeyFormat format = factory.keyFormats().get(template).keyFormat;

    manager.validateKey(factory.createKey(format));
  }

  @Test
  public void validateKey_failsWithInvalidVersion() throws Exception {
    HpkeKeyFormat format =
        factory.keyFormats().get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM").keyFormat;
    HpkePrivateKey key = HpkePrivateKey.newBuilder(factory.createKey(format)).setVersion(1).build();

    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_failsWithMissingPublicKey() throws Exception {
    HpkeKeyFormat format =
        factory.keyFormats().get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM").keyFormat;
    HpkePrivateKey key =
        HpkePrivateKey.newBuilder(factory.createKey(format)).clearPublicKey().build();

    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_failsWithEmptyPrivateKey() throws Exception {
    HpkeKeyFormat format =
        factory.keyFormats().get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM").keyFormat;
    HpkePrivateKey key =
        HpkePrivateKey.newBuilder(factory.createKey(format)).clearPrivateKey().build();

    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void getPublicKey() throws Exception {
    HpkeKeyFormat format =
        factory.keyFormats().get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM").keyFormat;
    HpkePrivateKey key = factory.createKey(format);

    assertThat(manager.getPublicKey(key)).isEqualTo(key.getPublicKey());
  }

  @Test
  public void parseKey() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM);
    HpkePrivateKey privateKey = factory.createKey(format);

    assertThat(manager.parseKey(privateKey.toByteString())).isEqualTo(privateKey);
  }

  @Test
  public void parseKeyFormat() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM);

    assertThat(factory.parseKeyFormat(format.toByteString())).isEqualTo(format);
  }

  @Test
  public void createPrimitive() throws Exception {
    HpkeKeyFormat format =
        createKeyFormat(
            HpkeKem.DHKEM_X25519_HKDF_SHA256, HpkeKdf.HKDF_SHA256, HpkeAead.AES_128_GCM);
    HpkePrivateKey privateKey = factory.createKey(format);
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
    String publicKeyUrl = new HpkePublicKeyManager().getKeyType();
    String privateKeyUrl = new HpkePrivateKeyManager().getKeyType();

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.getKeyManager(publicKeyUrl, HybridEncrypt.class));
    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.getKeyManager(privateKeyUrl, HybridDecrypt.class));

    HpkePrivateKeyManager.registerPair(/*newKeyAllowed=*/ true);

    Registry.getKeyManager(publicKeyUrl, HybridEncrypt.class);
    Registry.getKeyManager(privateKeyUrl, HybridDecrypt.class);
  }
}
