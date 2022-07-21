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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Unit tests for {@link AeadWrapper}. */
@RunWith(Theories.class)
public class AeadWrapperTest {

  private static AesCtrHmacAeadKey aesCtrHmacAeadKey;
  private static AesCtrHmacAeadKey aesCtrHmacAeadKey2;

  @BeforeClass
  public static void setUpClass() throws Exception {
    AeadConfig.register();

    int aesKeySize = 16;
    int hmacKeySize = 20;
    int ivSize = 12;
    int tagSize = 16;
    aesCtrHmacAeadKey =
        AesCtrHmacAeadKey.newBuilder()
        .setAesCtrKey(TestUtil.createAesCtrKey(Random.randBytes(aesKeySize), ivSize))
        .setHmacKey(TestUtil.createHmacKey(Random.randBytes(hmacKeySize), tagSize)).build();
    aesCtrHmacAeadKey2 =
        AesCtrHmacAeadKey.newBuilder()
        .setAesCtrKey(TestUtil.createAesCtrKey(Random.randBytes(aesKeySize), ivSize))
        .setHmacKey(TestUtil.createHmacKey(Random.randBytes(hmacKeySize), tagSize)).build();
  }

  private static Key getKey(
      AesCtrHmacAeadKey aesCtrHmacAeadKey, int keyId, OutputPrefixType prefixType)
      throws Exception {
    return TestUtil.createKey(
        TestUtil.createKeyData(
            aesCtrHmacAeadKey,
            "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
            KeyData.KeyMaterialType.SYMMETRIC),
        keyId,
        KeyStatusType.ENABLED,
        prefixType);
  }

  @Theory
  public void wrappedRawEncrypt_canBeDecryptedByRawPrimitive() throws Exception {
    Key key = getKey(aesCtrHmacAeadKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    Aead rawAead = Registry.getPrimitive(key.getKeyData(), Aead.class);

    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimaryPrimitive(rawAead, key)
            .build();
    Aead wrappedAead = new AeadWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = wrappedAead.encrypt(plaintext, associatedData);

    assertThat(rawAead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void wrappedRawDecrypt_decryptsRawCiphertext() throws Exception {
    Key key = getKey(aesCtrHmacAeadKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW);
    Aead rawAead = Registry.getPrimitive(key.getKeyData(), Aead.class);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] rawCiphertext = rawAead.encrypt(plaintext, associatedData);

    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimaryPrimitive(rawAead, key)
            .build();
    Aead wrappedAead = new AeadWrapper().wrap(primitives);

    assertThat(wrappedAead.decrypt(rawCiphertext, associatedData)).isEqualTo(plaintext);
    byte[] invalid = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class, () -> wrappedAead.decrypt(rawCiphertext, invalid));
    assertThrows(
        GeneralSecurityException.class, () -> wrappedAead.decrypt(invalid, associatedData));
    byte[] ciphertextWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), rawCiphertext);
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedAead.decrypt(ciphertextWithTinkPrefix, associatedData));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedAead.decrypt("".getBytes(UTF_8), associatedData));
  }

  @Theory
  public void wrappedNonRawEncrypt_addsPrefixToRawCiphertext() throws Exception {
    Key key = getKey(aesCtrHmacAeadKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    Aead rawAead = Registry.getPrimitive(key.getKeyData(), Aead.class);

    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimaryPrimitive(rawAead, key)
            .build();
    Aead wrappedAead = new AeadWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = wrappedAead.encrypt(plaintext, associatedData);

    byte[] tinkPrefix = Arrays.copyOf(ciphertext, 5);
    byte[] ciphertextWithoutPrefix =
        Arrays.copyOfRange(ciphertext, 5, ciphertext.length);
    assertThat(tinkPrefix).isEqualTo(TestUtil.hexDecode("0166AABBCC"));
    assertThat(rawAead.decrypt(ciphertextWithoutPrefix, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void wrappedNonRawDecrypt_decryptsRawCiphertextWithPrefix() throws Exception {
    Key key = getKey(aesCtrHmacAeadKey, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK);
    Aead rawAead = Registry.getPrimitive(key.getKeyData(), Aead.class);

    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimaryPrimitive(rawAead, key)
            .build();
    Aead wrappedAead = new AeadWrapper().wrap(primitives);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] rawCiphertext = rawAead.encrypt(plaintext, associatedData);
    byte[] rawCiphertextWithTinkPrefix =
        Bytes.concat(TestUtil.hexDecode("0166AABBCC"), rawCiphertext);

    assertThat(wrappedAead.decrypt(rawCiphertextWithTinkPrefix, associatedData))
        .isEqualTo(plaintext);

    byte[] invalid = "invalid".getBytes(UTF_8);
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedAead.decrypt(rawCiphertextWithTinkPrefix, invalid));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedAead.decrypt(invalid, associatedData));
    assertThrows(
        GeneralSecurityException.class,
        () -> wrappedAead.decrypt("".getBytes(UTF_8), associatedData));
  }

  @DataPoints("outputPrefixType")
  public static final OutputPrefixType[] OUTPUT_PREFIX_TYPES =
      new OutputPrefixType[] {
        OutputPrefixType.LEGACY,
        OutputPrefixType.CRUNCHY,
        OutputPrefixType.TINK,
        OutputPrefixType.RAW
      };

  @Theory
  public void encrytAndDecrypt_success(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix) throws Exception {
    Key key = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, prefix);
    Aead aead =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key), Aead.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);

    byte[] invalid = "invalid".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, invalid));
    assertThrows(
        GeneralSecurityException.class,
        () -> aead.decrypt(invalid, associatedData));
    assertThrows(
        GeneralSecurityException.class,
        () -> aead.decrypt("".getBytes(UTF_8), associatedData));

    // decrypt with a different key should fail
    Key otherKey = getKey(aesCtrHmacAeadKey2, /*keyId=*/ 234, prefix);
    Aead otherAead =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(otherKey), Aead.class));
    assertThrows(
        GeneralSecurityException.class, () -> otherAead.decrypt(ciphertext, associatedData));
  }

  @Theory
  public void decryptWorksIfCiphertextIsValidForAnyPrimitiveInThePrimitiveSet(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix1,
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix2)
      throws Exception {
    Key key1 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, prefix1);
    Key key2 = getKey(aesCtrHmacAeadKey2, /*keyId=*/ 234, prefix2);
    Aead aead1 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), Aead.class));
    Aead aead2 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), Aead.class));
    Aead aead12 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1, key2), Aead.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext1 = aead1.encrypt(plaintext, associatedData);
    byte[] ciphertext2 = aead2.encrypt(plaintext, associatedData);
    assertThat(aead12.decrypt(ciphertext1, associatedData)).isEqualTo(plaintext);
    assertThat(aead12.decrypt(ciphertext2, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void encryptUsesPrimaryPrimitive()
      throws Exception {
    Key key1 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, OutputPrefixType.TINK);
    Key key2 = getKey(aesCtrHmacAeadKey2, /*keyId=*/ 234, OutputPrefixType.TINK);
    Aead aead1 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), Aead.class));
    Aead aead2 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), Aead.class));
    Aead aead12 =
        new AeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(/*primary=*/ key1, key2), Aead.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead12.encrypt(plaintext, associatedData);

    // key1 is the primary key of aead12. Therefore, aead1 should be able to decrypt, and aead2 not.
    assertThat(aead1.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class, () -> aead2.decrypt(ciphertext, associatedData));
  }

  @Theory
  public void decryptFailsIfEncryptedWithOtherKeyEvenIfKeyIdsAreEqual(
      @FromDataPoints("outputPrefixType") OutputPrefixType prefix) throws Exception {
    Key key1 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, prefix);
    Key key2 = getKey(aesCtrHmacAeadKey2, /*keyId=*/ 123, prefix);

    Aead aead =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), Aead.class));
    Aead aead2 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), Aead.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThrows(
        GeneralSecurityException.class, () -> aead2.decrypt(ciphertext, associatedData));
  }

  @DataPoints("nonRawOutputPrefixType")
  public static final OutputPrefixType[] NON_RAW_OUTPUT_PREFIX_TYPES =
      new OutputPrefixType[] {
        OutputPrefixType.LEGACY, OutputPrefixType.CRUNCHY, OutputPrefixType.TINK
      };

  @Theory
  public void nonRawKeysWithSameKeyMaterialButDifferentKeyIds_decryptFails(
      @FromDataPoints("nonRawOutputPrefixType") OutputPrefixType prefix) throws Exception {
    Key key1 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, prefix);
    Key key2 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 234, prefix);

    Aead aead =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), Aead.class));
    Aead aead2 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), Aead.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThrows(
        GeneralSecurityException.class, () -> aead2.decrypt(ciphertext, associatedData));
  }

  @Theory
  public void rawKeysWithSameKeyMaterialButDifferentKeyIds_decryptWorks() throws Exception {
    Key key1 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, OutputPrefixType.RAW);
    Key key2 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 234, OutputPrefixType.RAW);

    Aead aead =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), Aead.class));
    Aead aead2 =
        new AeadWrapper()
            .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), Aead.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead2.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void noPrimary_decryptWorks() throws Exception {
    Key key = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, OutputPrefixType.TINK);
    Aead rawAead = Registry.getPrimitive(key.getKeyData(), Aead.class);

    Aead wrappedAead = new AeadWrapper().wrap(
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimaryPrimitive(rawAead, key)
            .build());
    Aead wrappedAeadWithoutPrimary = new AeadWrapper().wrap(
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimitive(rawAead, key)
            .build());

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = wrappedAead.encrypt(plaintext, associatedData);
    assertThat(wrappedAeadWithoutPrimary.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Theory
  public void noPrimary_encryptThrowsNullPointerException() throws Exception {
    Key key = getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, OutputPrefixType.TINK);
    Aead rawAead = Registry.getPrimitive(key.getKeyData(), Aead.class);

    Aead wrappedAeadWithoutPrimary = new AeadWrapper().wrap(
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimitive(rawAead, key)
            .build());

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    // This usually should not happen, since the wrapper is generated by KeysetHandle,
    // which validates the keyset. See getPrimitiveFromKeysetHandleWithoutPrimary_throws test.
    assertThrows(
        NullPointerException.class,
        () -> wrappedAeadWithoutPrimary.encrypt(plaintext, associatedData));
  }

  @Theory
  public void getPrimitiveFromKeysetHandleWithoutPrimary_throws() throws Exception {
    Keyset keysetWithoutPrimary =
        Keyset.newBuilder()
            .addKey(getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, OutputPrefixType.TINK))
            .build();
    KeysetHandle keysetHandle = CleartextKeysetHandle.fromKeyset(keysetWithoutPrimary);
    assertThrows(
        GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void testAeadWithoutAnnotations_hasNoMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    Aead aead =
        new AeadWrapper()
            .wrap(
                TestUtil.createPrimitiveSet(
                    TestUtil.createKeyset(
                        getKey(aesCtrHmacAeadKey, /*keyId=*/ 123, OutputPrefixType.TINK)),
                    Aead.class));

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(ciphertext, "invalid".getBytes(UTF_8)));

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testAeadWithAnnotations_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    Key key1 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 42, OutputPrefixType.TINK);
    Key key2 = getKey(aesCtrHmacAeadKey, /*keyId=*/ 43, OutputPrefixType.RAW);

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

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<Aead> primitives =
        PrimitiveSet.newBuilder(Aead.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(
                new AlwaysFailingAead(),
                getKey(aesCtrHmacAeadKey, /*keyId=*/ 42, OutputPrefixType.TINK))
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
