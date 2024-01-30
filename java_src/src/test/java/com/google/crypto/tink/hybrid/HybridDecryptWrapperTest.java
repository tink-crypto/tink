// Copyright 2022 Google LLC
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
import static com.google.crypto.tink.internal.Util.isPrefix;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.subtle.EciesAeadHkdfHybridDecrypt;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBigInteger;
import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.runner.RunWith;

/** Tests for {@link HybridDecryptWrapper}. */
@RunWith(Theories.class)
public class HybridDecryptWrapperTest {
  @Before
  public void setUp() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    HybridConfig.register();
  }

  @Test
  public void decryptNoPrefix_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    HybridDecrypt decrypter = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt encrypter =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getPrimary().getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void decryptTink_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    HybridDecrypt decrypter = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt encrypter =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getPrimary().getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void decryptCrunchy_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.CRUNCHY)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    HybridDecrypt decrypter = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt encrypter =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getPrimary().getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void decrypt_worksForEveryTinkKey() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .build();
    HybridDecrypt decrypter = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt encrypter0 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(0).getKey());
    HybridEncrypt encrypter1 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(1).getKey());
    HybridEncrypt encrypter2 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(2).getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter0.encrypt(message, context), context)).isEqualTo(message);
    assertThat(decrypter.decrypt(encrypter1.encrypt(message, context), context)).isEqualTo(message);
    assertThat(decrypter.decrypt(encrypter2.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void decrypt_worksForEveryNoPrefixKey() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .build();
    HybridDecrypt decrypter = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt encrypter0 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(0).getKey());
    HybridEncrypt encrypter1 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(1).getKey());
    HybridEncrypt encrypter2 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(2).getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter0.encrypt(message, context), context)).isEqualTo(message);
    assertThat(decrypter.decrypt(encrypter1.encrypt(message, context), context)).isEqualTo(message);
    assertThat(decrypter.decrypt(encrypter2.encrypt(message, context), context)).isEqualTo(message);
  }

  /**
   * This test checks that we decrypt ciphertext even if it is encrypted under a NO_PREFIX
   * non-primary, the primary is a Tink prefix primary, and the ciphertext matches the prefix by a
   * 2^(-40) probability coincidence.
   */
  @Test
  public void decrypt_rawCiphertextLookingLikeTinkCiphertext_createTest() throws Exception {
    // We are using LEGACY_UNCOMPRESSED because we can make the ciphertext start with 0x01 for this.
    EciesParameters parameters =
        EciesParameters.builder()
            .setCurveType(EciesParameters.CurveType.NIST_P256)
            .setHashType(EciesParameters.HashType.SHA256)
            .setNistCurvePointFormat(EciesParameters.PointFormat.LEGACY_UNCOMPRESSED)
            .setVariant(EciesParameters.Variant.NO_PREFIX)
            .setDemParameters(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    EciesPublicKey publicKey =
        EciesPublicKey.createForNistCurve(
            parameters,
            new ECPoint(
                new BigInteger(
                    "cc38c424b8c88e0d5726e0b05017b597e92c3dd8be412a458d12172180c6badd", 16),
                new BigInteger(
                    "6ef995bf8e6a392dd038d0543b6f57f3e2283d0dc3a1c470faf6d4d0299ad80e", 16)),
            /* idRequirement= */ null);
    // This is now a private key for which we have a known ciphertext which starts with "0x01".
    EciesPrivateKey privateKey =
        EciesPrivateKey.createForNistCurve(
            publicKey,
            SecretBigInteger.fromBigInteger(
                new BigInteger(
                    "57bd0131ccab56735932597e9414c4e9f6ed4a2d780f93d7d03573023100de5e", 16),
                InsecureSecretKeyAccess.get()));
    // We verify the above claim first to make sure the test is correct.
    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    byte[] ciphertext =
        Hex.decode(
            "01ae4755bd"
                + "66be54fdbfc60907e1ba0801dcc2f9a25c049f8fe1c2578d509019d048fd9dd2718b9b940711c0"
                + "10b86ca28786eb5a7b93da42ccd2ac950ea2614295f1bd6b0ad91e0369044ecfdd2fae8f31811472"
                + "426e4410fce68191f2cfe5aa");
    {
      HybridDecrypt decrypt = EciesAeadHkdfHybridDecrypt.create(privateKey);
      assertThat(decrypt.decrypt(ciphertext, context)).isEqualTo(message);
    }
    HpkeParameters tinkHpkeParameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(tinkHpkeParameters)
                    .withFixedId(0xae4755bd)
                    .makePrimary())
            .addEntry(KeysetHandle.importKey(privateKey).withRandomId())
            .build();

    HybridDecrypt keysetHandleDecrypt = handle.getPrimitive(HybridDecrypt.class);
    assertThat(keysetHandleDecrypt.decrypt(ciphertext, context)).isEqualTo(message);

    HybridEncrypt encrypt = handle.getPublicKeysetHandle().getPrimitive(HybridEncrypt.class);
    byte[] primaryCiphertext = encrypt.encrypt(message, context);
    assertThat(keysetHandleDecrypt.decrypt(primaryCiphertext, context)).isEqualTo(message);
    assertThat(isPrefix(Hex.decode("01ae4755bd"), primaryCiphertext)).isTrue();
  }

  @Test
  public void monitorsWithAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    HybridDecryptWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt encrypter =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getPrimary().getKey());
    byte[] data = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    byte[] ciphertext = encrypter.encrypt(data, context);
    assertThat(decrypter.decrypt(ciphertext, context)).isEqualTo(data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry signEntry = logEntries.get(0);
    assertThat(signEntry.getKeyId()).isEqualTo(123);
    assertThat(signEntry.getPrimitive()).isEqualTo("hybrid_decrypt");
    assertThat(signEntry.getApi()).isEqualTo("decrypt");
    assertThat(signEntry.getNumBytesAsInput()).isEqualTo(ciphertext.length - 5);
    assertThat(signEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void monitorsWithAnnotation_correctKeyIsAssociated() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    HybridDecryptWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        HpkeParameters.builder()
                            .setVariant(HpkeParameters.Variant.NO_PREFIX)
                            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                            .build())
                    .withFixedId(100))
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(200).makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withFixedId(300))
            .setMonitoringAnnotations(annotations)
            .build();

    HybridDecrypt decrypter = handle.getPrimitive(HybridDecrypt.class);
    HybridEncrypt encrypter0 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(0).getKey());
    HybridEncrypt encrypter1 =
        HpkeEncrypt.create((HpkePublicKey) handle.getPublicKeysetHandle().getAt(1).getKey());
    byte[] context = "context".getBytes(UTF_8);
    byte[] ciphertext0 = encrypter0.encrypt(new byte[100], context);
    Object unused = decrypter.decrypt(ciphertext0, context);
    byte[] ciphertext1 = encrypter1.encrypt(new byte[200], context);
    unused = decrypter.decrypt(ciphertext1, context);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry signEntry0 = logEntries.get(0);
    assertThat(signEntry0.getKeyId()).isEqualTo(100);
    assertThat(signEntry0.getPrimitive()).isEqualTo("hybrid_decrypt");
    assertThat(signEntry0.getApi()).isEqualTo("decrypt");
    assertThat(signEntry0.getNumBytesAsInput()).isEqualTo(ciphertext0.length);
    assertThat(signEntry0.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry signEntry1 = logEntries.get(1);
    assertThat(signEntry1.getKeyId()).isEqualTo(200);
    assertThat(signEntry1.getPrimitive()).isEqualTo("hybrid_decrypt");
    assertThat(signEntry1.getApi()).isEqualTo("decrypt");
    assertThat(signEntry1.getNumBytesAsInput()).isEqualTo(ciphertext1.length - 5);
    assertThat(signEntry1.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
