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

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.subtle.EcdsaSignJce;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link PublicKeyVerifyWrapper}. */
@RunWith(JUnit4.class)
public class PublicKeyVerifyWrapperTest {
  @Before
  public void setUp() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    SignatureConfig.register();
  }

  @Test
  public void verifyNoPrefix_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  /** We test all variants for legacy reasons. */
  @Test
  public void verifyTink_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.TINK)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Test
  public void verifyCrunchy_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.CRUNCHY)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Test
  public void verifyLegacy_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.LEGACY)
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);

    verifier.verify(sig, data);
  }

  @Test
  public void verifyTriesAllKeys_works() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .build();
    PublicKeySign signer0 = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(0).getKey());
    PublicKeySign signer1 = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(1).getKey());
    PublicKeySign signer2 = EcdsaSignJce.create((EcdsaPrivateKey) handle.getAt(2).getKey());
    PublicKeyVerify verifier = handle.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    verifier.verify(signer0.sign(data), data);
    verifier.verify(signer1.sign(data), data);
    verifier.verify(signer2.sign(data), data);
  }

  @Test
  public void verifyRequiresCorrectKey_fails() throws Exception {
    EcdsaParameters parameters =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();
    KeysetHandle handle1 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withRandomId())
            .build();
    KeysetHandle handle2 =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withRandomId().makePrimary())
            .build();
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) handle2.getAt(0).getKey());
    PublicKeyVerify verifier = handle1.getPublicKeysetHandle().getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(sig, data));
  }

  @Test
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

    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder(privateHandle.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(0).getKey());
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry verifyEntry = logEntries.get(0);
    assertThat(verifyEntry.getKeyId()).isEqualTo(123);
    assertThat(verifyEntry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verifyEntry.getApi()).isEqualTo("verify");
    assertThat(verifyEntry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(verifyEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(0);
  }

  @Test
  public void monitorsWithAnnotations_failure_shortSignature() throws Exception {
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

    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder(privateHandle.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(new byte[] {1, 2, 3}, data));

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry verifyFailure = failures.get(0);
    assertThat(verifyFailure.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verifyFailure.getApi()).isEqualTo("verify");
    assertThat(verifyFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void monitorsWithAnnotations_failure_longSignature() throws Exception {
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

    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder(privateHandle.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();
    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(0).getKey());
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] wrongSig = signer.sign(new byte[0]);
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(wrongSig, data));

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry verifyFailure = failures.get(0);
    assertThat(verifyFailure.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verifyFailure.getApi()).isEqualTo("verify");
    assertThat(verifyFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @Test
  public void monitors_associatesWithCorrectKey_works() throws Exception {
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
    EcdsaParameters parametersNoPrefix =
        EcdsaParameters.builder()
            .setSignatureEncoding(EcdsaParameters.SignatureEncoding.IEEE_P1363)
            .setCurveType(EcdsaParameters.CurveType.NIST_P256)
            .setHashType(EcdsaParameters.HashType.SHA256)
            .setVariant(EcdsaParameters.Variant.NO_PREFIX)
            .build();

    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParameters(parameters).withFixedId(20))
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parametersNoPrefix)
                    .withFixedId(30)
                    .makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParameters(parametersNoPrefix).withFixedId(40))
            .build();
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder(privateHandle.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeySign signer20 = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(0).getKey());
    PublicKeySign signer30 = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(1).getKey());
    PublicKeySign signer40 = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(2).getKey());
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    // Verify once with data of length 2 for key with id 20.
    byte[] data = "da".getBytes(UTF_8);
    byte[] sig = signer20.sign(data);
    verifier.verify(sig, data);

    // Verify once with data of length 3 for key with id 30.
    data = "dat".getBytes(UTF_8);
    sig = signer30.sign(data);
    verifier.verify(sig, data);

    // Verify once with data of length 4 for key with id 40.
    data = "data".getBytes(UTF_8);
    sig = signer40.sign(data);
    verifier.verify(sig, data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(3);
    FakeMonitoringClient.LogEntry verify0Entry = logEntries.get(0);
    assertThat(verify0Entry.getKeyId()).isEqualTo(20);
    assertThat(verify0Entry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verify0Entry.getApi()).isEqualTo("verify");
    assertThat(verify0Entry.getNumBytesAsInput()).isEqualTo(2);
    assertThat(verify0Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry verify1Entry = logEntries.get(1);
    assertThat(verify1Entry.getKeyId()).isEqualTo(30);
    assertThat(verify1Entry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verify1Entry.getApi()).isEqualTo("verify");
    assertThat(verify1Entry.getNumBytesAsInput()).isEqualTo(3);
    assertThat(verify1Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry verify2Entry = logEntries.get(2);
    assertThat(verify2Entry.getKeyId()).isEqualTo(40);
    assertThat(verify2Entry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verify2Entry.getApi()).isEqualTo("verify");
    assertThat(verify2Entry.getNumBytesAsInput()).isEqualTo(4);
    assertThat(verify2Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(0);
  }

  @Test
  public void monitorsWithAnnotations_legacySameLength() throws Exception {
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

    KeysetHandle privateHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParameters(parameters).withFixedId(123).makePrimary())
            .build();
    KeysetHandle publicHandle =
        KeysetHandle.newBuilder(privateHandle.getPublicKeysetHandle())
            .setMonitoringAnnotations(annotations)
            .build();

    PublicKeySign signer = EcdsaSignJce.create((EcdsaPrivateKey) privateHandle.getAt(0).getKey());
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);

    byte[] data = "data".getBytes(UTF_8);
    byte[] sig = signer.sign(data);
    verifier.verify(sig, data);

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(1);
    FakeMonitoringClient.LogEntry verifyEntry = logEntries.get(0);
    assertThat(verifyEntry.getKeyId()).isEqualTo(123);
    assertThat(verifyEntry.getPrimitive()).isEqualTo("public_key_verify");
    assertThat(verifyEntry.getApi()).isEqualTo("verify");
    // For keys of type legacy we report 1 more.
    assertThat(verifyEntry.getNumBytesAsInput()).isEqualTo(data.length);
    assertThat(verifyEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(0);
  }
}
