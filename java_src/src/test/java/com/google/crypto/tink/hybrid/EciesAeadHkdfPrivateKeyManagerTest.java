// Copyright 2017 Google LLC
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
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.hybrid.internal.testing.EciesAeadHkdfTestUtil;
import com.google.crypto.tink.hybrid.internal.testing.HybridTestVector;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.math.BigInteger;
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

/** Tests for EciesAeadHkdfPrivateKeyManager. */
@RunWith(Theories.class)
public class EciesAeadHkdfPrivateKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
    HybridConfig.register();
  }

  @Test
  public void testEciesP256HkdfHmacSha256Aes128GcmTemplate() throws Exception {
    KeyTemplate template =
        EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128GcmTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                .setVariant(EciesParameters.Variant.TINK)
                .setDemParameters(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build());
  }

  @Test
  public void testRawEciesP256HkdfHmacSha256Aes128GcmCompressedTemplate() throws Exception {
    KeyTemplate template =
        EciesAeadHkdfPrivateKeyManager.rawEciesP256HkdfHmacSha256Aes128GcmCompressedTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    AesGcmParameters.builder()
                        .setIvSizeBytes(12)
                        .setKeySizeBytes(16)
                        .setTagSizeBytes(16)
                        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                        .build())
                .build());
  }

  @Test
  public void testEciesP256HkdfHmacSha256Aes128CtrHmacSha256Template() throws Exception {
    KeyTemplate template =
        EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128CtrHmacSha256Template();

    assertThat(template.toParameters())
        .isEqualTo(
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.UNCOMPRESSED)
                .setVariant(EciesParameters.Variant.TINK)
                .setDemParameters(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build());
  }

  @Test
  public void testRawEciesP256HkdfHmacSha256Aes128CtrHmacSha256CompressedTemplate()
      throws Exception {
    KeyTemplate template =
        EciesAeadHkdfPrivateKeyManager
            .rawEciesP256HkdfHmacSha256Aes128CtrHmacSha256CompressedTemplate();

    assertThat(template.toParameters())
        .isEqualTo(
            EciesParameters.builder()
                .setCurveType(EciesParameters.CurveType.NIST_P256)
                .setHashType(EciesParameters.HashType.SHA256)
                .setNistCurvePointFormat(EciesParameters.PointFormat.COMPRESSED)
                .setVariant(EciesParameters.Variant.NO_PREFIX)
                .setDemParameters(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p =
        EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128GcmTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p =
        EciesAeadHkdfPrivateKeyManager.rawEciesP256HkdfHmacSha256Aes128GcmCompressedTemplate()
            .toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p =
        EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128CtrHmacSha256Template()
            .toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p =
        EciesAeadHkdfPrivateKeyManager
            .rawEciesP256HkdfHmacSha256Aes128CtrHmacSha256CompressedTemplate()
            .toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
        "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM_RAW",
        "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM",
        "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM_RAW",
        "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
        "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW",
        "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
        "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256_RAW",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void createKey_nistCurve_alwaysDifferent() throws Exception {
    Parameters params = KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM").toParameters();

    int numKeys = 10;
    Set<BigInteger> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      EciesPrivateKey key = (EciesPrivateKey) handle.getPrimary().getKey();
      keys.add(key.getNistPrivateKeyValue().getBigInteger(InsecureSecretKeyAccess.get()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createKey_x25519Curve_throws() throws Exception {
    Parameters params =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.X25519)
            .setHashType(EciesParameters.HashType.SHA256)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(params));
  }

  @Test
  public void createPrimitive_x25519Curve_throws() throws Exception {
    EciesParameters params =
        EciesParameters.builder()
            .setHashType(EciesParameters.HashType.SHA256)
            .setCurveType(EciesParameters.CurveType.X25519)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(XChaCha20Poly1305Parameters.create())
            .build();

    byte[] privateKeyBytes = X25519.generatePrivateKey();
    byte[] publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes);

    EciesPublicKey publicKey =
        EciesPublicKey.createForCurveX25519(
            params, Bytes.copyFrom(publicKeyBytes), /* idRequirement= */ null);
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForCurveX25519(
            publicKey, SecretBytes.copyFrom(privateKeyBytes, InsecureSecretKeyAccess.get()));

    KeysetHandle.Builder.Entry entry =
        KeysetHandle.importKey(privateKey).makePrimary().withRandomId();
    KeysetHandle handle = KeysetHandle.newBuilder().addEntry(entry).build();
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(HybridDecrypt.class));
  }

  @DataPoints("testVectors")
  public static final HybridTestVector[] HYBRID_TEST_VECTORS =
      EciesAeadHkdfTestUtil.createEciesTestVectors();

  @Theory
  public void test_decryptCiphertext_works(@FromDataPoints("testVectors") HybridTestVector v)
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
  public void test_decryptWrongContextInfo_throws(@FromDataPoints("testVectors") HybridTestVector v)
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
  public void test_encryptThenDecryptMessage_works(
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
  public void test_serializeAndParse_works() throws Exception {
    HybridTestVector testVector = HYBRID_TEST_VECTORS[0];
    EciesPrivateKey key = (EciesPrivateKey) testVector.getPrivateKey();
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
    EciesPrivateKey key = (EciesPrivateKey) testVector.getPrivateKey();
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
                    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
                    HybridDecrypt.class))
        .isNotNull();
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey",
                    HybridEncrypt.class))
        .isNotNull();
  }
}
