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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
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
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AeadWrapper */
@RunWith(JUnit4.class)
public class AeadWrapperTest {
  private static final int AES_KEY_SIZE = 16;
  private static final int HMAC_KEY_SIZE = 20;

  @BeforeClass
  public static void setUp() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void testBasicAesCtrHmacAeadWithoutAnnotation() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;
    PrimitiveSet<Aead> primitives =
        TestUtil.createPrimitiveSet(
            TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createAesCtrHmacAeadKeyData(
                        aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.TINK)),
            Aead.class);
    Aead aead = new AeadWrapper().wrap(primitives);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertArrayEquals(plaintext, decrypted);
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[0]));

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testMultipleKeys() throws Exception {
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key primary =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Key raw =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            43,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    Key legacy =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);

    Key tink =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            45,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);

    Aead aead =
        new AeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(primary, raw, legacy, tink), Aead.class));
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] prefix = Arrays.copyOf(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE);

    assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(primary));
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertThat(ciphertext)
        .hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE + plaintext.length + ivSize + tagSize);

    // encrypt with a non-primary RAW key and decrypt with the keyset
    Aead aead2 =
        new AeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(TestUtil.createKeyset(raw, legacy, tink), Aead.class));
    ciphertext = aead2.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));

    // encrypt with a random key not in the keyset, decrypt with the keyset should fail
    byte[] aesCtrKeyValue2 = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue2 = Random.randBytes(HMAC_KEY_SIZE);
    Key random =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue2, ivSize, hmacKeyValue2, tagSize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    aead2 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(random), Aead.class));
    final byte[] ciphertext2 = aead2.encrypt(plaintext, associatedData);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> aead.decrypt(ciphertext2, associatedData));
    assertExceptionContains(e, "decryption failed");
  }

  @Test
  public void testRawKeyAsPrimary() throws Exception {
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key primary =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    Key raw =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            43,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    Key legacy =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);
    Aead aead =
        new AeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(primary, raw, legacy), Aead.class));
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertThat(ciphertext)
        .hasLength(CryptoFormat.RAW_PREFIX_SIZE + plaintext.length + ivSize + tagSize);
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key primary =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    Aead aead =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(primary), Aead.class));
    byte[] plaintext = Random.randBytes(1);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertThat(ciphertext)
        .hasLength(CryptoFormat.RAW_PREFIX_SIZE + plaintext.length + ivSize + tagSize);
  }

  @Test
  public void testAeadWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    byte[] aesCtrKeyValue1 = Random.randBytes(AES_KEY_SIZE);
    byte[] aesCtrKeyValue2 = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;

    Key key1 =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue1, ivSize, hmacKeyValue, tagSize),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Key key2 =
        TestUtil.createKey(
            TestUtil.createAesCtrHmacAeadKeyData(aesCtrKeyValue2, ivSize, hmacKeyValue, tagSize),
            43,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);

    byte[] plaintext = Random.randBytes(20);
    byte[] plaintext2 = Random.randBytes(30);
    byte[] associatedData = Random.randBytes(40);

    // generate ciphertext2 using key2
    Aead aead2 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), Aead.class));
    byte[] ciphertext2 = aead2.encrypt(plaintext2, associatedData);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<Aead> primitives =
        TestUtil.createPrimitiveSetWithAnnotations(
            TestUtil.createKeyset(key1, key2), // key1 is the primary key
            annotations,
            Aead.class);
    Aead aead = new AeadWrapper().wrap(primitives);

    byte[] ciphertext = aead.encrypt(plaintext, associatedData);  // uses key1 to encrypt
    byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
    byte[] decrypted2 = aead.decrypt(ciphertext2, associatedData);
    assertThat(decrypted2).isEqualTo(plaintext2);

    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[0]));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(3);
    FakeMonitoringClient.LogEntry encEntry = logEntries.get(0);
    assertThat(encEntry.getKeyId()).isEqualTo(42);
    assertThat(encEntry.getPrimitive()).isEqualTo("aead");
    assertThat(encEntry.getApi()).isEqualTo("encrypt");
    assertThat(encEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(encEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry decEntry = logEntries.get(1);
    assertThat(decEntry.getKeyId()).isEqualTo(42);
    assertThat(decEntry.getPrimitive()).isEqualTo("aead");
    assertThat(decEntry.getApi()).isEqualTo("decrypt");
    // ciphertext was encrypted with key1, which has a TINK ouput prefix. This adds a 5 bytes prefix
    // to the ciphertext. This prefix is not included in getNumBytesAsInput.
    assertThat(decEntry.getNumBytesAsInput())
        .isEqualTo(ciphertext.length - CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertThat(decEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry dec2Entry = logEntries.get(2);
    assertThat(dec2Entry.getKeyId()).isEqualTo(43);
    assertThat(dec2Entry.getPrimitive()).isEqualTo("aead");
    assertThat(dec2Entry.getApi()).isEqualTo("decrypt");
    // ciphertext2 was encrypted with key2, which has a RAW ouput prefix.
    assertThat(dec2Entry.getNumBytesAsInput()).isEqualTo(ciphertext2.length);
    assertThat(dec2Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry decFailure = failures.get(0);
    assertThat(decFailure.getPrimitive()).isEqualTo("aead");
    assertThat(decFailure.getApi()).isEqualTo("decrypt");
    assertThat(decFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(decFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  private static class AlwaysFailingAead implements Aead {
    public AlwaysFailingAead() {}

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Test
  public void testFailingAeadWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    byte[] aesCtrKeyValue = Random.randBytes(AES_KEY_SIZE);
    byte[] hmacKeyValue = Random.randBytes(HMAC_KEY_SIZE);
    int ivSize = 12;
    int tagSize = 16;
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(
                new AlwaysFailingAead(),
                TestUtil.createKey(
                    TestUtil.createAesCtrHmacAeadKeyData(
                        aesCtrKeyValue, ivSize, hmacKeyValue, tagSize),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.TINK))
            .build();
    Aead aead = new AeadWrapper().wrap(primitives);

    byte[] randomBytes = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(randomBytes, associatedData));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(randomBytes, associatedData));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(2);
    FakeMonitoringClient.LogFailureEntry encFailure = failures.get(0);
    assertThat(encFailure.getPrimitive()).isEqualTo("aead");
    assertThat(encFailure.getApi()).isEqualTo("encrypt");
    assertThat(encFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(encFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogFailureEntry decFailure = failures.get(1);
    assertThat(decFailure.getPrimitive()).isEqualTo("aead");
    assertThat(decFailure.getApi()).isEqualTo("decrypt");
    assertThat(decFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(decFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

}
