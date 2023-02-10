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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.mac.HmacParameters.HashType;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for MacWrapper. */
@RunWith(JUnit4.class)
public class MacWrapperTest {
  private static final int HMAC_KEY_SIZE = 20;
  private static final int HMAC_TAG_SIZE = 10;
  private static final int AES_CMAC_KEY_SIZE = 32;
  private static final int AES_CMAC_TAG_SIZE = 10;

  private static HmacKey rawKey0;
  private static HmacKey rawKey1;
  private static AesCmacKey rawKey2;
  private static AesCmacKey rawKey3;
  private static HmacKey tinkKey0;
  private static AesCmacKey tinkKey1;
  private static HmacKey crunchyKey0;
  private static AesCmacKey crunchyKey1;
  private static HmacKey legacyKey0;
  private static AesCmacKey legacyKey1;

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    AesCmacProtoSerialization.register();
    HmacProtoSerialization.register();
    createTestKeys();
  }

  private static void createTestKeys() {
    final HmacParameters noPrefixHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.NO_PREFIX);
    final HmacParameters legacyHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.LEGACY);
    final HmacParameters crunchyHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.CRUNCHY);
    final HmacParameters tinkHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.TINK);
    final AesCmacParameters noPrefixAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.NO_PREFIX);
    final AesCmacParameters legacyAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.LEGACY);
    final AesCmacParameters crunchyAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.CRUNCHY);
    final AesCmacParameters tinkAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.TINK);

    try {
      rawKey0 =
          HmacKey.builder()
              .setParameters(noPrefixHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      rawKey1 =
          HmacKey.builder()
              .setParameters(noPrefixHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      rawKey2 =
          AesCmacKey.builder()
              .setParameters(noPrefixAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      rawKey3 =
          AesCmacKey.builder()
              .setParameters(noPrefixAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      tinkKey0 =
          HmacKey.builder()
              .setParameters(tinkHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(4)
              .build();
      tinkKey1 =
          AesCmacKey.builder()
              .setParameters(tinkAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(5)
              .build();
      crunchyKey0 =
          HmacKey.builder()
              .setParameters(crunchyHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(6)
              .build();
      crunchyKey1 =
          AesCmacKey.builder()
              .setParameters(crunchyAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(7)
              .build();
      legacyKey0 =
          HmacKey.builder()
              .setParameters(legacyHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(8)
              .build();
      legacyKey1 =
          AesCmacKey.builder()
              .setParameters(legacyAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(9)
              .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static AesCmacParameters createDefaultAesCmacParameters(
      AesCmacParameters.Variant variant) {
    try {
      return AesCmacParameters.builder()
          .setKeySizeBytes(AES_CMAC_KEY_SIZE)
          .setTagSizeBytes(AES_CMAC_TAG_SIZE)
          .setVariant(variant)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static HmacParameters createDefaultHmacParameters(HmacParameters.Variant variant) {
    try {
      return HmacParameters.builder()
          .setKeySizeBytes(HMAC_KEY_SIZE)
          .setTagSizeBytes(HMAC_TAG_SIZE)
          .setVariant(variant)
          .setHashType(HashType.SHA1)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Incorrect parameters creation arguments", e);
    }
  }

  @Test
  public void testComputeVerifyMac_works() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle smallKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234).makePrimary())
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .build();
    Mac mac = smallKeysetHandle.getPrimitive(Mac.class);

    byte[] tag = mac.computeMac(plaintext);

    mac.verifyMac(tag, plaintext);
  }

  @Test
  public void testComputeVerifyMac_throwsOnWrongKey() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle computeKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234).makePrimary())
            .build();
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235).makePrimary())
            .build();
    Mac computingMac = computeKeysetHandle.getPrimitive(Mac.class);
    Mac verifyingMac = verifyKeysetHandle.getPrimitive(Mac.class);

    byte[] tag = computingMac.computeMac(plaintext);

    assertThrows(GeneralSecurityException.class, () -> verifyingMac.verifyMac(tag, plaintext));
  }

  @Test
  public void testVerifyMac_checksAllNecessaryRawKeys() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle computeKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237).makePrimary())
            .build();
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .build();
    Mac computingMac = computeKeysetHandle.getPrimitive(Mac.class);
    Mac verifyingMac = verifyKeysetHandle.getPrimitive(Mac.class);

    byte[] tag = computingMac.computeMac(plaintext);

    verifyingMac.verifyMac(tag, plaintext);
  }

  @Test
  public void testVerifyMac_checksRawKeysWhenTagHasTinkKeyPrefix() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] tag = Hex.decode("0152af9740d2fab0cf3f");
    HmacKey rawKey5 =
        HmacKey.builder()
            .setParameters(createDefaultHmacParameters(HmacParameters.Variant.NO_PREFIX))
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("7d40a4d7c192ca113f403b8703e1b7b93fecf99a"),
                    InsecureSecretKeyAccess.get()))
            .setIdRequirement(null)
            .build();
    // Note: 0x52af97f0 are bytes 1 to 4 in the tag.
    HmacKey tinkKey2 =
        HmacKey.builder()
            .setParameters(createDefaultHmacParameters(HmacParameters.Variant.TINK))
            .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
            .setIdRequirement(0x52af9740)
            .build();
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey5).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(tinkKey2).makePrimary())
            .build();

    Mac mac = verifyKeysetHandle.getPrimitive(Mac.class);

    mac.verifyMac(tag, plaintext);
  }

  @Test
  public void computeMac_usesPrimaryKey() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .build();
    KeysetHandle keysetHandlePrimary =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236).makePrimary())
            .build();
    Mac computingMac = keysetHandle.getPrimitive(Mac.class);
    Mac verifyingMac = keysetHandlePrimary.getPrimitive(Mac.class);

    byte[] tag = computingMac.computeMac(plaintext);

    verifyingMac.verifyMac(tag, plaintext);
  }

  @Test
  public void testComputeVerifyMac_manyKeysWork() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle assortedKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234))
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236))
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey0))
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .addEntry(KeysetHandle.importKey(crunchyKey0))
            .addEntry(KeysetHandle.importKey(crunchyKey1).makePrimary())
            .addEntry(KeysetHandle.importKey(legacyKey0))
            .addEntry(KeysetHandle.importKey(legacyKey1))
            .build();
    Mac mac = assortedKeysetHandle.getPrimitive(Mac.class);

    byte[] tag = mac.computeMac(plaintext);

    mac.verifyMac(tag, plaintext);
  }

  @Test
  public void testVerifyMac_shiftedPrimaryWithManyKeysWorks() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle assortedKeysetHandle0 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234))
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236))
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey0))
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .addEntry(KeysetHandle.importKey(crunchyKey0))
            .addEntry(KeysetHandle.importKey(crunchyKey1).makePrimary())
            .addEntry(KeysetHandle.importKey(legacyKey0))
            .addEntry(KeysetHandle.importKey(legacyKey1))
            .build();
    KeysetHandle.Builder assortedBuilder = KeysetHandle.newBuilder(assortedKeysetHandle0);
    assortedBuilder.getAt(4).makePrimary();
    KeysetHandle assortedKeysetHandle1 = assortedBuilder.build();
    Mac mac = assortedKeysetHandle1.getPrimitive(Mac.class);

    byte[] tag = mac.computeMac(plaintext);

    mac.verifyMac(tag, plaintext);
  }

  // ------------------------------------------------------------------------------ Monitoring tests

  @Test
  public void testMultipleKeysWithoutAnnotation() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    byte[] plaintext = "plaintext".getBytes(UTF_8);
    KeysetHandle mainKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234))
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236))
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey0))
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .addEntry(KeysetHandle.importKey(crunchyKey0))
            .addEntry(KeysetHandle.importKey(crunchyKey1).makePrimary())
            .addEntry(KeysetHandle.importKey(legacyKey1))
            .build();
    KeysetHandle noPrefixKeyKeyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236).makePrimary())
            .build();
    KeysetHandle prefixedKeyKeyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(crunchyKey1).makePrimary())
            .build();
    KeysetHandle missingKeyKeyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(legacyKey0).makePrimary())
            .build();
    Mac mac = mainKeysetHandle.getPrimitive(Mac.class);
    Mac noPrefixMac = noPrefixKeyKeyset.getPrimitive(Mac.class);
    Mac prefixedMac = prefixedKeyKeyset.getPrimitive(Mac.class);
    Mac missingMac = missingKeyKeyset.getPrimitive(Mac.class);

    // Busy work triggering different code paths.
    byte[] tag = noPrefixMac.computeMac(plaintext);
    mac.verifyMac(tag, plaintext);
    tag = prefixedMac.computeMac(plaintext);
    mac.verifyMac(tag, plaintext);
    byte[] missingTag = missingMac.computeMac(plaintext);
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(missingTag, plaintext));

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testWithAnnotation_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    Key tinkKey =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(Random.randBytes(HMAC_KEY_SIZE), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Key rawKey =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(Random.randBytes(HMAC_KEY_SIZE), 16),
            43,
            KeyStatusType.ENABLED,
            OutputPrefixType.RAW);
    Key legacyKey =
        TestUtil.createKey(
            TestUtil.createHmacKeyData(Random.randBytes(HMAC_KEY_SIZE), 16),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.LEGACY);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    Mac rawMac =
        new MacWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(rawKey), annotations, Mac.class));
    Mac legacyMac =
        new MacWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(legacyKey), annotations, Mac.class));
    Mac mac =
        new MacWrapper()
            .wrap(
                TestUtil.createPrimitiveSetWithAnnotations(
                    TestUtil.createKeyset(tinkKey, rawKey, legacyKey), annotations, Mac.class));
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] tinkTag = mac.computeMac(plaintext);
    byte[] rawTag = rawMac.computeMac(plaintext);
    byte[] legacyTag = legacyMac.computeMac(plaintext);
    mac.verifyMac(tinkTag, plaintext);
    mac.verifyMac(rawTag, plaintext);
    mac.verifyMac(legacyTag, plaintext);
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tinkTag, new byte[0]));

    List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
    assertThat(logEntries).hasSize(6);

    FakeMonitoringClient.LogEntry tinkComputeEntry = logEntries.get(0);
    assertThat(tinkComputeEntry.getKeyId()).isEqualTo(42);
    assertThat(tinkComputeEntry.getPrimitive()).isEqualTo("mac");
    assertThat(tinkComputeEntry.getApi()).isEqualTo("compute");
    assertThat(tinkComputeEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(tinkComputeEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry rawComputeEntry = logEntries.get(1);
    assertThat(rawComputeEntry.getKeyId()).isEqualTo(43);
    assertThat(rawComputeEntry.getPrimitive()).isEqualTo("mac");
    assertThat(rawComputeEntry.getApi()).isEqualTo("compute");
    assertThat(rawComputeEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(rawComputeEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry legacyComputeEntry = logEntries.get(2);
    assertThat(legacyComputeEntry.getKeyId()).isEqualTo(44);
    assertThat(legacyComputeEntry.getPrimitive()).isEqualTo("mac");
    assertThat(legacyComputeEntry.getApi()).isEqualTo("compute");
    // legacy mac appends one byte to the input data, therefore the input length is one longer.
    assertThat(legacyComputeEntry.getNumBytesAsInput()).isEqualTo(plaintext.length + 1);
    assertThat(legacyComputeEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry tinkVerifyEntry = logEntries.get(3);
    assertThat(tinkVerifyEntry.getKeyId()).isEqualTo(42);
    assertThat(tinkVerifyEntry.getPrimitive()).isEqualTo("mac");
    assertThat(tinkVerifyEntry.getApi()).isEqualTo("verify");
    assertThat(tinkVerifyEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(tinkVerifyEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry rawVerifyEntry = logEntries.get(4);
    assertThat(rawVerifyEntry.getKeyId()).isEqualTo(43);
    assertThat(rawVerifyEntry.getPrimitive()).isEqualTo("mac");
    assertThat(rawVerifyEntry.getApi()).isEqualTo("verify");
    assertThat(rawVerifyEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
    assertThat(rawVerifyEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogEntry legacyVerifyEntry = logEntries.get(5);
    assertThat(legacyVerifyEntry.getKeyId()).isEqualTo(44);
    assertThat(legacyVerifyEntry.getPrimitive()).isEqualTo("mac");
    assertThat(legacyVerifyEntry.getApi()).isEqualTo("verify");
    // legacy mac appends one byte to the input data, therefore the input length is one longer.
    assertThat(legacyVerifyEntry.getNumBytesAsInput()).isEqualTo(plaintext.length + 1);
    assertThat(legacyVerifyEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(1);
    FakeMonitoringClient.LogFailureEntry verifyFailure = failures.get(0);
    assertThat(verifyFailure.getPrimitive()).isEqualTo("mac");
    assertThat(verifyFailure.getApi()).isEqualTo("verify");
    assertThat(verifyFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(verifyFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  public static class AlwaysFailingMac implements Mac {
    @Override
    public byte[] computeMac(final byte[] data) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }

    @Override
    public void verifyMac(final byte[] mac, final byte[] data) throws GeneralSecurityException {
      throw new GeneralSecurityException("fail");
    }
  }

  @Test
  public void testAlwaysFailingWithAnnotation_hasMonitoring() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    PrimitiveSet<Mac> primitives =
        PrimitiveSet.newBuilder(Mac.class)
            .setAnnotations(annotations)
            .addPrimaryPrimitive(
                new AlwaysFailingMac(),
                TestUtil.createKey(
                    TestUtil.createHmacKeyData(Random.randBytes(HMAC_KEY_SIZE), 16),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.TINK))
            .build();
    Mac mac = new MacWrapper().wrap(primitives);

    byte[] data = "some data".getBytes(UTF_8);
    byte[] invalidTag = "an invalid tag".getBytes(UTF_8);

    assertThrows(GeneralSecurityException.class, () -> mac.computeMac(data));
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(invalidTag, data));

    // Test short tags, because there is a different code path for this.
    byte[] shortInvalidTag = "t".getBytes(UTF_8);
    assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(shortInvalidTag, data));

    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();

    List<FakeMonitoringClient.LogFailureEntry> failures =
        fakeMonitoringClient.getLogFailureEntries();
    assertThat(failures).hasSize(3);
    FakeMonitoringClient.LogFailureEntry compFailure = failures.get(0);
    assertThat(compFailure.getPrimitive()).isEqualTo("mac");
    assertThat(compFailure.getApi()).isEqualTo("compute");
    assertThat(compFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(compFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogFailureEntry verifyFailure = failures.get(1);
    assertThat(verifyFailure.getPrimitive()).isEqualTo("mac");
    assertThat(verifyFailure.getApi()).isEqualTo("verify");
    assertThat(verifyFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(verifyFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);

    FakeMonitoringClient.LogFailureEntry verifyFailure2 = failures.get(2);
    assertThat(verifyFailure2.getPrimitive()).isEqualTo("mac");
    assertThat(verifyFailure2.getApi()).isEqualTo("verify");
    assertThat(verifyFailure2.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
    assertThat(verifyFailure2.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }
}
