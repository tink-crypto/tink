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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link PublicKeySignWrapper}. */
@RunWith(Theories.class)
public class PublicKeySignWrapperTest {
  @Before
  public void setUp() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    SignatureConfig.register();
  }

  @Test
  public void signNoPrefix_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

    PublicKeyVerify verifier =
        EcdsaVerifyJce.create((EcdsaPublicKey) handle.getPublicKeysetHandle().getAt(0).getKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  /** We test all variants for legacy reasons. */
  @Test
  public void signTink_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

    PublicKeyVerify verifier =
        EcdsaVerifyJce.create((EcdsaPublicKey) handle.getPublicKeysetHandle().getAt(0).getKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Test
  public void signCrunchy_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

    PublicKeyVerify rawVerifier =
        EcdsaVerifyJce.create((EcdsaPublicKey) handle.getPublicKeysetHandle().getAt(0).getKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    rawVerifier.verify(sig, data);
  }

  @Test
  public void signLegacy_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

    PublicKeyVerify verifier =
        EcdsaVerifyJce.create((EcdsaPublicKey) handle.getPublicKeysetHandle().getAt(0).getKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Theory
  public void usesPrimaryToSign() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .build();

    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

    PublicKeyVerify verifier =
        EcdsaVerifyJce.create((EcdsaPublicKey) handle.getPublicKeysetHandle().getAt(1).getKey());

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Theory
  public void getPrimitiveNoPrimary_throwsNullPointerException() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    Keyset keyset =
        Keyset.parseFrom(
            TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()),
            ExtensionRegistryLite.getEmptyRegistry());
    Keyset keysetWithoutPrimary = keyset.toBuilder().clearPrimaryKeyId().build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            TinkProtoKeysetFormat.parseKeyset(
                    keysetWithoutPrimary.toByteArray(), InsecureSecretKeyAccess.get())
                .getPrimitive(PublicKeySign.class));
  }

  @Theory
  public void doesNotMonitorWithoutAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    PublicKeySignWrapper.register();

    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

    byte[] data = "data".getBytes(UTF_8);
    Object unused = signer.sign(data);

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Theory
  public void monitorsWithAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    PublicKeySignWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);
    byte[] data = "data".getBytes(UTF_8);
    Object unused = signer.sign(data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry signEntry = logEntries.get(0);
    assertThat(signEntry.getKeyId()).isEqualTo(123);
    assertThat(signEntry.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(signEntry.getApi()).isEqualTo("sign");
    assertThat(signEntry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(signEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @Theory
  public void monitorsWithAnnotations_legacyDataLengthIsOneBigger() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    PublicKeySignWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);
    byte[] data = "data".getBytes(UTF_8);
    Object unused = signer.sign(data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry signEntry = logEntries.get(0);
    assertThat(signEntry.getKeyId()).isEqualTo(123);
    assertThat(signEntry.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(signEntry.getApi()).isEqualTo("sign");
    assertThat(signEntry.getNumBytesAsInput()).isEqualTo(data.length + 1);
    assertThat(signEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @Theory
  public void monitorsWithAnnotations_multipleSigners_works() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    PublicKeySignWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();

    KeysetHandle handle1 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();
    KeysetHandle handle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(456).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeySign signer1 = handle1.getPrimitive(PublicKeySign.class);
    PublicKeySign signer2 = handle2.getPrimitive(PublicKeySign.class);
    byte[] data = "data".getBytes(UTF_8);
    Object unused = signer1.sign(data);
    unused = signer2.sign(data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(2);
    FakeMonitoringClient.LogEntry sign1Entry = logEntries.get(0);
    assertThat(sign1Entry.getKeyId()).isEqualTo(123);
    assertThat(sign1Entry.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(sign1Entry.getApi()).isEqualTo("sign");
    assertThat(sign1Entry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(sign1Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
    FakeMonitoringClient.LogEntry sign2Entry = logEntries.get(1);
    assertThat(sign2Entry.getKeyId()).isEqualTo(456);
    assertThat(sign2Entry.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(sign2Entry.getApi()).isEqualTo("sign");
    assertThat(sign2Entry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(sign2Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  private static class AlwaysFailingPublicKeySign implements PublicKeySign {
    public AlwaysFailingPublicKeySign(EcdsaPrivateKey key) {}

    @Override
    public byte[] sign(byte[] data) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Theory
  public void testAlwaysFailingPublicKeySignWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                AlwaysFailingPublicKeySign::new, EcdsaPrivateKey.class, PublicKeySign.class));
    PublicKeySignWrapper.register();

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeySign signer = handle.getPrimitive(PublicKeySign.class);

    byte[] data = "data".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> signer.sign(data));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry signFailure = failures.get(0);
    assertThat(signFailure.getPrimitive()).isEqualTo("public_key_sign");
    assertThat(signFailure.getApi()).isEqualTo("sign");
    assertThat(signFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(123);
    assertThat(signFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
