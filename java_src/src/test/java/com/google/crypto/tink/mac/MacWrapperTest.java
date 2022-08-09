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
import static com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for MacWrapper. */
@RunWith(JUnit4.class)
public class MacWrapperTest {
  private static final int HMAC_KEY_SIZE = 20;

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
  }

  @Test
  public void testMultipleKeysWithoutAnnotation() throws Exception {
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().clear();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    Key tink = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          42,
          KeyStatusType.ENABLED,
          OutputPrefixType.TINK);
    Key legacy = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          43,
          KeyStatusType.ENABLED,
          OutputPrefixType.LEGACY);
    Key raw = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          44,
          KeyStatusType.ENABLED,
          OutputPrefixType.RAW);
    Key crunchy = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue, 16),
          45,
          KeyStatusType.ENABLED,
          OutputPrefixType.CRUNCHY);
    Key[] keys = new Key[] {tink, legacy, raw, crunchy};
    int j = keys.length;
    for (int i = 0; i < j; i++) {
      PrimitiveSet<Mac> primitives =
          TestUtil.createPrimitiveSet(
              TestUtil.createKeyset(
                  keys[i], keys[(i + 1) % j], keys[(i + 2) % j], keys[(i + 3) % j]),
              Mac.class);
      Mac mac = new MacWrapper().wrap(primitives);
      byte[] plaintext = "plaintext".getBytes(UTF_8);
      byte[] tag = mac.computeMac(plaintext);
      if (!keys[i].getOutputPrefixType().equals(OutputPrefixType.RAW)) {
        byte[] prefix = Arrays.copyOf(tag, CryptoFormat.NON_RAW_PREFIX_SIZE);
        assertArrayEquals(prefix, CryptoFormat.getOutputPrefix(keys[i]));
      }
      try {
        mac.verifyMac(tag, plaintext);
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid MAC, should not throw exception: " + i, e);
      }

      // Modify plaintext or tag and make sure the verifyMac failed.
      byte[] plaintextAndTag = Bytes.concat(plaintext, tag);
      for (int b = 0; b < plaintextAndTag.length; b++) {
        for (int bit = 0; bit < 8; bit++) {
          byte[] modified = Arrays.copyOf(plaintextAndTag, plaintextAndTag.length);
          modified[b] ^= (byte) (1 << bit);
          assertThrows(
              GeneralSecurityException.class,
              () ->
                  mac.verifyMac(
                      Arrays.copyOfRange(modified, plaintext.length, modified.length),
                      Arrays.copyOf(modified, plaintext.length)));
        }
      }

      // mac with a non-primary RAW key, verify with the keyset
      PrimitiveSet<Mac> primitives2 =
          TestUtil.createPrimitiveSet(TestUtil.createKeyset(raw, legacy, tink, crunchy), Mac.class);
      Mac mac2 = new MacWrapper().wrap(primitives2);
      tag = mac2.computeMac(plaintext);
      try {
        mac.verifyMac(tag, plaintext);
      } catch (GeneralSecurityException e) {
        throw new AssertionError("Valid MAC, should not throw exception", e);
      }

      // mac with a random key not in the keyset, verify with the keyset should fail
      byte[] keyValue2 = Random.randBytes(HMAC_KEY_SIZE);
      Key random = TestUtil.createKey(
          TestUtil.createHmacKeyData(keyValue2, 16),
          44,
          KeyStatusType.ENABLED,
          OutputPrefixType.TINK);
      PrimitiveSet<Mac> primitives3 =
          TestUtil.createPrimitiveSet(TestUtil.createKeyset(random), Mac.class);
      mac2 = new MacWrapper().wrap(primitives3);
      byte[] tag2 = mac2.computeMac(plaintext);
      assertThrows(GeneralSecurityException.class, () -> mac.verifyMac(tag2, plaintext));
    }

    // Without annotations, nothing gets logged.
    assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
    assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  }

  @Test
  public void testSmallPlaintextWithRawKey() throws Exception {
    byte[] keyValue = Random.randBytes(HMAC_KEY_SIZE);
    Key primary = TestUtil.createKey(
        TestUtil.createHmacKeyData(keyValue, 16),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    PrimitiveSet<Mac> primitives =
        TestUtil.createPrimitiveSet(TestUtil.createKeyset(primary), Mac.class);
    Mac mac = new MacWrapper().wrap(primitives);
    byte[] plaintext = "blah".getBytes(UTF_8);
    byte[] tag = mac.computeMac(plaintext);
    // no prefix
    assertThat(tag).hasLength(16);
    try {
      mac.verifyMac(tag, plaintext);
    } catch (GeneralSecurityException e) {
      throw new AssertionError("Valid MAC, should not throw exception", e);
    }
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

  // Returns a key whose output prefix is taken from
  private static com.google.crypto.tink.Key parseKeyWithProgrammableOutputPrefix(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access) {
    com.google.crypto.tink.util.Bytes outputPrefix =
        com.google.crypto.tink.util.Bytes.copyFrom(serialization.getValue().toByteArray());
    return new MacKey() {
      @Override
      public com.google.crypto.tink.util.Bytes getOutputPrefix() {
        return outputPrefix;
      }

      @Override
      public MacParameters getParameters() {
        return new MacParameters() {
          @Override
          public boolean hasIdRequirement() {
            throw new UnsupportedOperationException("Not needed in test");
          }
        };
      }

      @Override
      public Integer getIdRequirementOrNull() {
        throw new UnsupportedOperationException("Not needed in test");
      }

      @Override
      public boolean equalsKey(com.google.crypto.tink.Key k) {
        throw new UnsupportedOperationException("Not needed in test");
      }
    };
  }

  private static final String TYPE_URL_FOR_PROGRAMMABLE_KEY = "typeUrlForProgrammableKey";
  @BeforeClass
  public static void registerProgrammableOutputPrefixKey() throws Exception {
    MutableSerializationRegistry.globalInstance()
        .registerKeyParser(
            KeyParser.create(
                MacWrapperTest::parseKeyWithProgrammableOutputPrefix,
                toBytesFromPrintableAscii(TYPE_URL_FOR_PROGRAMMABLE_KEY),
                ProtoKeySerialization.class));
  }

  @Test
  public void correctOutputPrefixInKey_creatingWorks() throws Exception {
    Key key =
        Key.newBuilder()
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(
                KeyData.newBuilder()
                    .setTypeUrl(TYPE_URL_FOR_PROGRAMMABLE_KEY)
                    .setValue(ByteString.copyFrom(new byte[] {0x01, 0x01, 0x02, 0x03, 0x04}))
                    .setKeyMaterialType(KeyMaterialType.SYMMETRIC))
            .setKeyId(0x01020304)
            .setStatus(KeyStatusType.ENABLED)
            .build();
    // Wrapping would throw before any mac is computed, so we can use any Mac for the test.
    PrimitiveSet<Mac> primitives =
        PrimitiveSet.newBuilder(Mac.class).addPrimaryPrimitive(new AlwaysFailingMac(), key).build();
    new MacWrapper().wrap(primitives);
  }

  @Test
  public void wrongOutputPrefixInKey_creationFails() throws Exception {
    Key key =
        Key.newBuilder()
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(
                KeyData.newBuilder()
                    .setTypeUrl(TYPE_URL_FOR_PROGRAMMABLE_KEY)
                    .setValue(ByteString.copyFrom(new byte[] {0x01, 0x01, 0x02, 0x03, 0x04}))
                    .setKeyMaterialType(KeyMaterialType.SYMMETRIC))
            .setKeyId(0x01020305)
            .setStatus(KeyStatusType.ENABLED)
            .build();
    // Wrapping throws before any mac is computed, so we can use an AlwaysFailingMac for the test.
    PrimitiveSet<Mac> primitives =
        PrimitiveSet.newBuilder(Mac.class).addPrimaryPrimitive(new AlwaysFailingMac(), key).build();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> new MacWrapper().wrap(primitives));
    assertThat(e).hasMessageThat().contains("has wrong output prefix");
  }
}
