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

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for DeterministicAeadWrapper. */
@RunWith(JUnit4.class)
public class DeterministicAeadWrapperTest {
  private Integer[] keySizeInBytes;

  @BeforeClass
  public static void setUp() throws Exception {
    DeterministicAeadConfig.register();
  }

  @Before
  public void setUp2() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println(
          "Unlimited Strength Jurisdiction Policy Files are required"
              + " but not installed. Skip all DeterministicAeadFactory tests");
      keySizeInBytes = new Integer[] {};
    } else {
      keySizeInBytes = new Integer[] {64};
    }
  }

  @Test
  public void testEncrytDecryptWithoutAnnotations() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    PrimitiveSet<DeterministicAead> primitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createAesSivKeyData(64),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.TINK)),
            DeterministicAead.class);
    DeterministicAead aead = new DeterministicAeadWrapper().wrap(primitives);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = aead.encryptDeterministically(plaintext, associatedData);
    byte[] decrypted = aead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = aead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testMultipleKeys() throws Exception {
    for (int keySize : keySizeInBytes) {
      testMultipleKeys(keySize);
    }
  }

  private static void testMultipleKeys(int keySize) throws Exception {
    Key primary =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Key raw =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 43, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    Key legacy =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);
    Key tink =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            45,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    PrimitiveSet<DeterministicAead> primitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(primary, raw, legacy, tink), DeterministicAead.class);

    DeterministicAead daead = new DeterministicAeadWrapper().wrap(primitives);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);
    byte[] prefix = Arrays.copyOf(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(primary));
    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));
    assertThat(ciphertext).hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length + 16);

    // encrypt with a non-primary RAW key and decrypt with the keyset
    PrimitiveSet<DeterministicAead> primitives2 =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(raw, legacy, tink), DeterministicAead.class);
    DeterministicAead daead2 = new DeterministicAeadWrapper().wrap(primitives2);
    ciphertext = daead2.encryptDeterministically(plaintext, associatedData);
    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));

    // encrypt with a random key not in the keyset, decrypt with the keyset should fail
    Key random =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    primitives2 =
        TestUtil.createPrimitiveSet(TestUtil.createKeyset(random), DeterministicAead.class);
    daead2 = new DeterministicAeadWrapper().wrap(primitives2);
    ciphertext = daead2.encryptDeterministically(plaintext, associatedData);
    try {
      daead.decryptDeterministically(ciphertext, associatedData);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "decryption failed");
    }
  }

  @Test
  public void testRawKeyAsPrimary() throws Exception {
    for (int keySize : keySizeInBytes) {
      testRawKeyAsPrimary(keySize);
    }
  }

  private static void testRawKeyAsPrimary(int keySize) throws Exception {
    Key primary =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 42, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    Key raw =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 43, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    Key legacy =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);
    PrimitiveSet<DeterministicAead> primitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(primary, raw, legacy), DeterministicAead.class);

    DeterministicAead daead = new DeterministicAeadWrapper().wrap(primitives);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);

    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));
    assertThat(ciphertext).hasLength(CryptoFormat.RAW_PREFIX_SIZE + plaintext.length + 16);
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    for (int keySize : keySizeInBytes) {
      testSmallPlaintextWithRawKey(keySize);
    }
  }

  private static void testSmallPlaintextWithRawKey(int keySize) throws Exception {
    Key primary =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(keySize), 42, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    PrimitiveSet<DeterministicAead> primitives =
        TestUtil.createPrimitiveSet(TestUtil.createKeyset(primary), DeterministicAead.class);

    DeterministicAead daead = new DeterministicAeadWrapper().wrap(primitives);
    byte[] plaintext = Random.randBytes(1);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);

    assertArrayEquals(plaintext, daead.decryptDeterministically(ciphertext, associatedData));
    assertThat(ciphertext).hasLength(CryptoFormat.RAW_PREFIX_SIZE + plaintext.length + 16);
  }

  @Test
  public void testWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    Key primary =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(64), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK);
    Key key2 =
        TestUtil.createKey(
            TestUtil.createAesSivKeyData(64), 43, KeyStatusType.ENABLED, OutputPrefixType.RAW);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<DeterministicAead> primitives =
        TestUtil.createPrimitiveSetWithAnnotations(
            TestUtil.createKeyset(primary, key2), annotations, DeterministicAead.class);
    DeterministicAead daead = new DeterministicAeadWrapper().wrap(primitives);

    byte[] plaintext = Random.randBytes(20);
    byte[] plaintext2 = Random.randBytes(30);
    byte[] associatedData = Random.randBytes(40);

    // encrypt with a non-primary RAW key, without monitoring
    DeterministicAead daead2 =
        new DeterministicAeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), DeterministicAead.class));
    byte[] ciphertext2 = daead2.encryptDeterministically(plaintext2, associatedData);

    byte[] ciphertext = daead.encryptDeterministically(plaintext, associatedData);

    daead.decryptDeterministically(ciphertext, associatedData);
    daead.decryptDeterministically(ciphertext2, associatedData);
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
    // ciphertext was encrypted with primary, which has a TINK output prefix. This adds a 5 bytes
    // prefix to the ciphertext. This prefix is not included in getNumBytesAsInput.
    assertThat(decEntry.getNumBytesAsInput())
        .isEqualTo(ciphertext.length - CryptoFormat.NON_RAW_PREFIX_SIZE);
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
  public void testFailingAeadWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<DeterministicAead> primitives =
        PrimitiveSet.newBuilder(DeterministicAead.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(
                new AlwaysFailingDeterministicAead(),
                TestUtil.createKey(
                    TestUtil.createAesSivKeyData(64),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.TINK))
            .build();
    DeterministicAead daead = new DeterministicAeadWrapper().wrap(primitives);

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
