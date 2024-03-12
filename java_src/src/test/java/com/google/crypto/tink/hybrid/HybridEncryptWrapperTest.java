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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.Keyset;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for HybridEncryptWrapper. */
@RunWith(JUnit4.class)
public class HybridEncryptWrapperTest {
  @Before
  public void setUp() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    HybridConfig.register();
  }

  @Test
  public void encryptNoPrefix_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    HybridEncrypt encrypter = handle.getPublicKeysetHandle().getPrimitive(HybridEncrypt.class);
    HybridDecrypt decrypter = HpkeDecrypt.create((HpkePrivateKey) handle.getPrimary().getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void encryptTinkPrefix_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.TINK)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    HybridEncrypt encrypter = handle.getPublicKeysetHandle().getPrimitive(HybridEncrypt.class);
    HybridDecrypt decrypter = HpkeDecrypt.create((HpkePrivateKey) handle.getPrimary().getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void encryptCrunchyPrefix_works() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.CRUNCHY)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    HybridEncrypt encrypter = handle.getPublicKeysetHandle().getPrimitive(HybridEncrypt.class);
    HybridDecrypt decrypter = HpkeDecrypt.create((HpkePrivateKey) handle.getPrimary().getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void encryptEncryptsWithPrimary() throws Exception {
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

    HybridEncrypt encrypter = handle.getPublicKeysetHandle().getPrimitive(HybridEncrypt.class);
    HybridDecrypt decrypter = HpkeDecrypt.create((HpkePrivateKey) handle.getPrimary().getKey());

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThat(decrypter.decrypt(encrypter.encrypt(message, context), context)).isEqualTo(message);
  }

  @Test
  public void getPrimitiveNoPrimary_throwsNullPointerException() throws Exception {
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters).getPublicKeysetHandle();
    Keyset keyset =
        Keyset.parseFrom(
            TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle),
            ExtensionRegistryLite.getEmptyRegistry());
    Keyset keysetWithoutPrimary = keyset.toBuilder().clearPrimaryKeyId().build();
    // TODO(b/228140127) This should throw at primitive creation time.
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeysetWithoutSecret(keysetWithoutPrimary.toByteArray())
                .getPrimitive(HybridEncrypt.class)
                .encrypt(new byte[0], new byte[0]));
  }

  @Test
  public void doesNotMonitorWithoutAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    HybridEncryptWrapper.register();

    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    HybridEncrypt encrypt = handle.getPublicKeysetHandle().getPrimitive(HybridEncrypt.class);

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    Object unused = encrypt.encrypt(message, context);

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void monitorsWithAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    HybridEncryptWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();

    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder(privateHandle.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();

    HybridEncrypt encrypt = publicHandle.getPrimitive(HybridEncrypt.class);

    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    Object unused = encrypt.encrypt(message, context);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry encryptEntry = logEntries.get(0);
    assertThat(encryptEntry.getKeyId()).isEqualTo(123);
    assertThat(encryptEntry.getPrimitive()).isEqualTo("hybrid_encrypt");
    assertThat(encryptEntry.getApi()).isEqualTo("encrypt");
    assertThat(encryptEntry.getNumBytesAsInput()).isEqualTo(message.length);
    assertThat(encryptEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void monitorsWithAnnotations_multipleEncrypters_works() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    HybridEncryptWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();

    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();

    KeysetHandle privateHandle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();
    KeysetHandle publicHandle1 =
        KeysetHandle.newBuilder(privateHandle1.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();
    KeysetHandle privateHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(456).makePrimary())
            .build();
    KeysetHandle publicHandle2 =
        KeysetHandle.newBuilder(privateHandle2.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();

    HybridEncrypt encrypter1 = publicHandle1.getPrimitive(HybridEncrypt.class);
    HybridEncrypt encrypter2 = publicHandle2.getPrimitive(HybridEncrypt.class);
    byte[] message = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    Object unused = encrypter1.encrypt(message, context);
    unused = encrypter2.encrypt(message, context);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry encryptEntry1 = logEntries.get(0);
    assertThat(encryptEntry1.getKeyId()).isEqualTo(123);
    assertThat(encryptEntry1.getPrimitive()).isEqualTo("hybrid_encrypt");
    assertThat(encryptEntry1.getApi()).isEqualTo("encrypt");
    assertThat(encryptEntry1.getNumBytesAsInput()).isEqualTo(message.length);
    assertThat(encryptEntry1.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
    FakeMonitoringClient.LogEntry encryptEntry2 = logEntries.get(0);
    assertThat(encryptEntry2.getKeyId()).isEqualTo(123);
    assertThat(encryptEntry2.getPrimitive()).isEqualTo("hybrid_encrypt");
    assertThat(encryptEntry2.getApi()).isEqualTo("encrypt");
    assertThat(encryptEntry2.getNumBytesAsInput()).isEqualTo(message.length);
    assertThat(encryptEntry2.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  private static class AlwaysFailingHybridEncrypt implements HybridEncrypt {
    public AlwaysFailingHybridEncrypt(HpkePublicKey key) {}

    @Override
    public byte[] encrypt(byte[] message, byte[] contextInfo) throws GeneralSecurityException {
      throw new GeneralSecurityException("AlwaysFailingHybridEncrypt always fails");
    }
  }

  @Test
  public void testAlwaysFailingPublicKeySignWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                AlwaysFailingHybridEncrypt::new, HpkePublicKey.class, HybridEncrypt.class));
    HybridEncryptWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
            .build();
    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder(privateHandle.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();
    HybridEncrypt encrypt = publicHandle.getPrimitive(HybridEncrypt.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] context = "context".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> encrypt.encrypt(data, context));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry signFailure = failures.get(0);
    assertThat(signFailure.getPrimitive()).isEqualTo("hybrid_encrypt");
    assertThat(signFailure.getApi()).isEqualTo("encrypt");
    assertThat(signFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(123);
    assertThat(signFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void registerToInternalPrimitiveRegistry_works() throws Exception {
    PrimitiveRegistry.Builder initialBuilder = PrimitiveRegistry.builder();
    PrimitiveRegistry initialRegistry = initialBuilder.build();
    PrimitiveRegistry.Builder processedBuilder = PrimitiveRegistry.builder(initialRegistry);

    HybridEncryptWrapper.registerToInternalPrimitiveRegistry(processedBuilder);
    PrimitiveRegistry processedRegistry = processedBuilder.build();

    assertThrows(
        GeneralSecurityException.class,
        () -> initialRegistry.getInputPrimitiveClass(HybridEncrypt.class));
    assertThat(processedRegistry.getInputPrimitiveClass(HybridEncrypt.class))
        .isEqualTo(HybridEncrypt.class);
  }
}
