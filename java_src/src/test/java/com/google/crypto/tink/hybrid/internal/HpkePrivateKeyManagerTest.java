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
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.internal.testing.HpkeTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HybridTestVector;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;
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
  @BeforeClass
  public static void setUpClass() throws Exception {
    HybridConfig.register();
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
        "DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
        "DHKEM_P384_HKDF_SHA384_HKDF_SHA384_AES_256_GCM_RAW",
        "DHKEM_P521_HKDF_SHA512_HKDF_SHA512_AES_128_GCM",
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

  @DataPoints("testVectors")
  public static final HybridTestVector[] HYBRID_TEST_VECTORS = HpkeTestUtil.createHpkeTestVectors();

  @Theory
  public void decryptCiphertext_works(@FromDataPoints("testVectors") HybridTestVector v)
      throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    HybridDecrypt hybridDecrypt = handle.getPrimitive(HybridDecrypt.class);
    byte[] plaintext = hybridDecrypt.decrypt(v.getCiphertext(), v.getContextInfo());
    assertThat(Hex.encode(plaintext)).isEqualTo(Hex.encode(v.getPlaintext()));
  }

  @Theory
  public void decryptWrongContextInfo_throws(@FromDataPoints("testVectors") HybridTestVector v)
      throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    HybridDecrypt hybridDecrypt = handle.getPrimitive(HybridDecrypt.class);
    byte[] contextInfo = v.getContextInfo();
    if (contextInfo.length > 0) {
      contextInfo[0] ^= 1;
    } else {
      contextInfo = new byte[] {1};
    }
    // local variables referenced from a lambda expression must be final or effectively final
    final byte[] contextInfoCopy = Arrays.copyOf(contextInfo, contextInfo.length);
    assertThrows(
        GeneralSecurityException.class,
        () -> hybridDecrypt.decrypt(v.getCiphertext(), contextInfoCopy));
  }

  @Theory
  public void encryptThenDecryptMessage_works(
      @FromDataPoints("testVectors") HybridTestVector v) throws Exception {
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(v.getPrivateKey()).makePrimary();
    @Nullable Integer id = v.getPrivateKey().getIdRequirementOrNull();
    if (id == null) {
      entry.withRandomId();
    } else {
      entry.withFixedId(id);
    }
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    HybridDecrypt hybridDecrypt = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt hybridEncrypt = handle.getPublicKeysetHandle().getPrimitive(HybridEncrypt.class);
    byte[] ciphertext = hybridEncrypt.encrypt(v.getPlaintext(), v.getContextInfo());
    byte[] plaintext = hybridDecrypt.decrypt(ciphertext, v.getContextInfo());
    assertThat(Hex.encode(plaintext)).isEqualTo(Hex.encode(v.getPlaintext()));
  }

  @Test
  public void createKey_x25519_alwaysDifferent() throws Exception {
    Parameters params =
        KeyTemplates.get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM").toParameters();

    int numKeys = 10;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      HpkePrivateKey key = (HpkePrivateKey) handle.getPrimary().getKey();
      keys.add(Hex.encode(key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createKey_nistCurve_alwaysDifferent() throws Exception {
    Parameters params =
        KeyTemplates.get("DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW").toParameters();

    int numKeys = 10;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      HpkePrivateKey key = (HpkePrivateKey) handle.getPrimary().getKey();
      keys.add(Hex.encode(key.getPrivateKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void test_serializeAndParse_works() throws Exception {
    HybridTestVector testVector = HYBRID_TEST_VECTORS[0];
    HpkePrivateKey key = (HpkePrivateKey) testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).withFixedId(1216).makePrimary();
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();

    byte[] serializedHandle =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedHandle, InsecureSecretKeyAccess.get());
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
  }

  @Test
  public void test_serializeAndParse_publicKey_works() throws Exception {
    HybridTestVector testVector = HYBRID_TEST_VECTORS[0];
    HpkePrivateKey key = (HpkePrivateKey) testVector.getPrivateKey();
    KeysetHandle.Builder.Entry entry = KeysetHandle.importKey(key).withFixedId(1216).makePrimary();
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build().getPublicKeysetHandle();

    byte[] serializedHandle = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle);
    KeysetHandle parsedHandle = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedHandle);
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.HpkePrivateKey", HybridDecrypt.class))
        .isNotNull();
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.HpkePublicKey", HybridEncrypt.class))
        .isNotNull();
  }
}
