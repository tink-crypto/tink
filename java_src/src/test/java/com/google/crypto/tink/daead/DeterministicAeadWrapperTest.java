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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.daead.internal.AesSivProtoSerialization;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for DeterministicAeadWrapper. */
@RunWith(JUnit4.class)
public class DeterministicAeadWrapperTest {
  private static final int KEY_SIZE = 64;

  private static AesSivKey createKey(
      AesSivParameters.Variant variant, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    try {
      AesSivKey.Builder builder =
          AesSivKey.builder()
              .setParameters(
                  AesSivParameters.builder().setKeySizeBytes(KEY_SIZE).setVariant(variant).build())
              .setKeyBytes(SecretBytes.randomBytes(KEY_SIZE));
      if (idRequirement != null) {
        builder.setIdRequirement(idRequirement);
      }
      return builder.build();
    } catch (GeneralSecurityException e) {
      throw e;
    }
  }

  @Test
  public void encrytDecrypt_withoutAnnotations_noLogs() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    DeterministicAeadConfig.register();

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    AesSivKey tinkKey = createKey(AesSivParameters.Variant.TINK, 42);

    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(tinkKey).makePrimary()).build();
    DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);

    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = daead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void encryptDecrypt_keysetWithMultipleKeys_works() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    DeterministicAeadConfig.register();

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    AesSivKey tinkKey = createKey(AesSivParameters.Variant.TINK, 42);
    AesSivKey rawKey = createKey(AesSivParameters.Variant.NO_PREFIX, null);
    AesSivKey crunchyKey = createKey(AesSivParameters.Variant.CRUNCHY, 44);

    KeysetHandle mainKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(43))
            .addEntry(KeysetHandle.importKey(crunchyKey))
            .build();
    DeterministicAead daead = mainKeysetHandle.getPrimitive(DeterministicAead.class);

    // encrypt and decrypt with the main keyset works
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = daead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);
  }

  @Test
  public void encryptDecrypt_differentKeysets_works() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    DeterministicAeadConfig.register();

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    AesSivKey tinkKey = createKey(AesSivParameters.Variant.TINK, 42);
    AesSivKey rawKey = createKey(AesSivParameters.Variant.NO_PREFIX, null);

    KeysetHandle mainKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(43))
            .build();
    DeterministicAead daeadMain = mainKeysetHandle.getPrimitive(DeterministicAead.class);

    KeysetHandle rawKeyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(43).makePrimary())
            .build();
    DeterministicAead daeadRaw = rawKeyKeysetHandle.getPrimitive(DeterministicAead.class);

    // encrypt with RAW key (non-primary in the main keyset) and decrypt with the main keyset works
    byte[] ciphertext = daeadRaw.encryptDeterministically(plaintext, associatedData);

    assertArrayEquals(plaintext, daeadMain.decryptDeterministically(ciphertext, associatedData));
  }

  @Test
  public void encryptDecrypt_differentKeys_fails() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    DeterministicAeadConfig.register();

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    AesSivKey tinkKey0 = createKey(AesSivParameters.Variant.TINK, 42);
    AesSivKey tinkKey1 = createKey(AesSivParameters.Variant.TINK, 43);
    AesSivKey rawKey = createKey(AesSivParameters.Variant.NO_PREFIX, null);

    KeysetHandle mainKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey0).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(43))
            .build();
    DeterministicAead daead = mainKeysetHandle.getPrimitive(DeterministicAead.class);

    KeysetHandle otherKeyKeysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(tinkKey1).makePrimary()).build();
    DeterministicAead daead2 = otherKeyKeysetHandle.getPrimitive(DeterministicAead.class);

    // encrypt with a random key not in the main keyset, decrypt with the main keyset should fail
    byte[] ciphertext = daead2.encryptDeterministically(plaintext, associatedData);
    try {
      daead.decryptDeterministically(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }
  }

  @Test
  public void encryptDecrypt_rawKeyAsPrimary_works() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    DeterministicAeadConfig.register();

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    AesSivKey rawKey = createKey(AesSivParameters.Variant.NO_PREFIX, null);
    AesSivKey crunchyKey = createKey(AesSivParameters.Variant.CRUNCHY, 44);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(42).makePrimary())
            .addEntry(KeysetHandle.importKey(crunchyKey))
            .build();

    DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);

    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = daead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);
  }

  @Test
  public void encryptDecrypt_smallPlaintextWithRawKey_works() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    DeterministicAeadConfig.register();

    byte[] plaintext = Random.randBytes(1);
    byte[] associatedData = Random.randBytes(20);
    AesSivKey rawKey = createKey(AesSivParameters.Variant.NO_PREFIX, null);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(42).makePrimary())
            .build();

    DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);

    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = daead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = daead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = daead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);
  }

  @Test
  public void encryptDecrypt_withAnnotations_hasMonitoring() throws Exception {
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    DeterministicAeadConfig.register();

    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();

    byte[] plaintext = Random.randBytes(20);
    byte[] plaintext2 = Random.randBytes(30);
    byte[] associatedData = Random.randBytes(40);
    AesSivKey rawKey = createKey(AesSivParameters.Variant.NO_PREFIX, null);
    AesSivKey tinkKey = createKey(AesSivParameters.Variant.TINK, 42);

    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(43))
            .setMonitoringAnnotations(annotations)
            .build();
    DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);

    // encrypt with a non-primary RAW key, without monitoring
    KeysetHandle keysetHandle2 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey).withFixedId(43).makePrimary())
            .build();
    DeterministicAead daead2 = keysetHandle2.getPrimitive(DeterministicAead.class);

    byte[] ciphertext2 = daead2.encryptDeterministically(plaintext2, associatedData);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);

    Object unused = daead.decryptDeterministically(ciphertext, associatedData);
    unused = daead.decryptDeterministically(ciphertext2, associatedData);
    assertThrows(
        GeneralSecurityException.class,
        () -> daead.decryptDeterministically(ciphertext, new byte[0]));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(3);
    FakeMonitoringClient.LogEntry encEntry = logEntries.get(0);
    assertThat(encEntry.getKeyId()).isEqualTo(42);
    assertThat(encEntry.getPrimitive()).isEqualTo("daead");
    assertThat(encEntry.getApi()).isEqualTo("encrypt");
    assertThat(encEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(encEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry decEntry = logEntries.get(1);
    assertThat(decEntry.getKeyId()).isEqualTo(42);
    assertThat(decEntry.getPrimitive()).isEqualTo("daead");
    assertThat(decEntry.getApi()).isEqualTo("decrypt");
    assertThat(decEntry.getNumBytesAsInput()).isEqualTo(ciphertext.length);
    assertThat(decEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry dec2Entry = logEntries.get(2);
    assertThat(dec2Entry.getKeyId()).isEqualTo(43);
    assertThat(dec2Entry.getPrimitive()).isEqualTo("daead");
    assertThat(dec2Entry.getApi()).isEqualTo("decrypt");
    // ciphertext2 was encrypted with key2, which has a RAW ouput prefix.
    assertThat(dec2Entry.getNumBytesAsInput()).isEqualTo(ciphertext2.length);
    assertThat(dec2Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry decFailure = failures.get(0);
    assertThat(decFailure.getPrimitive()).isEqualTo("daead");
    assertThat(decFailure.getApi()).isEqualTo("decrypt");
    assertThat(decFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(decFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  private static class AlwaysFailingDeterministicAead implements DeterministicAead {

    AlwaysFailingDeterministicAead(AesSivKey key) {}

    @Override
    public byte[] encryptDeterministically(byte[] plaintext, byte[] associatedData)
        throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }

    @Override
    public byte[] decryptDeterministically(byte[] ciphertext, byte[] associatedData)
        throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Test
  public void encryptDecryptFailingDAead_withAnnotations_hasMonitoring() throws Exception {
    // Test setup.
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(
            PrimitiveConstructor.create(
                AlwaysFailingDeterministicAead::new, AesSivKey.class, DeterministicAead.class));
    DeterministicAeadWrapper.register();
    AesSivProtoSerialization.register();

    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    AesSivKey tinkKey = createKey(AesSivParameters.Variant.TINK, 42);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey).makePrimary())
            .setMonitoringAnnotations(annotations)
            .build();
    DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);

    byte[] randomBytes = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThrows(
        GeneralSecurityException.class,
        () -> daead.encryptDeterministically(randomBytes, associatedData));
    assertThrows(
        GeneralSecurityException.class,
        () -> daead.decryptDeterministically(randomBytes, associatedData));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(2);
    FakeMonitoringClient.LogFailureEntry encFailure = failures.get(0);
    assertThat(encFailure.getPrimitive()).isEqualTo("daead");
    assertThat(encFailure.getApi()).isEqualTo("encrypt");
    assertThat(encFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(encFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogFailureEntry decFailure = failures.get(1);
    assertThat(decFailure.getPrimitive()).isEqualTo("daead");
    assertThat(decFailure.getApi()).isEqualTo("decrypt");
    assertThat(decFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(decFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
