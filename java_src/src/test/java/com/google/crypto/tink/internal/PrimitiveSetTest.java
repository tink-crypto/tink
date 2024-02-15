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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for PrimitiveSet. */
@RunWith(JUnit4.class)
public class PrimitiveSetTest {

  private static class DummyMac1 implements Mac {
    public DummyMac1() {}

    @Override
    public byte[] computeMac(byte[] data) throws GeneralSecurityException {
      return this.getClass().getSimpleName().getBytes(UTF_8);
    }

    @Override
    public void verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
      return;
    }
  }

  private static class DummyMac2 implements Mac {
    public DummyMac2() {}

    @Override
    public byte[] computeMac(byte[] data) throws GeneralSecurityException {
      return this.getClass().getSimpleName().getBytes(UTF_8);
    }

    @Override
    public void verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
      return;
    }
  }

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    HmacKeyManager.register(true);
  }

  com.google.crypto.tink.Key getKeyFromProtoKey(Key key) throws GeneralSecurityException {
    @Nullable Integer idRequirement = key.getKeyId();
    if (key.getOutputPrefixType() == OutputPrefixType.RAW) {
      idRequirement = null;
    }
    return MutableSerializationRegistry.globalInstance()
        .parseKeyWithLegacyFallback(
            ProtoKeySerialization.create(
                key.getKeyData().getTypeUrl(),
                key.getKeyData().getValue(),
                key.getKeyData().getKeyMaterialType(),
                key.getOutputPrefixType(),
                idRequirement),
            InsecureSecretKeyAccess.get());
  }

  @Test
  public void primitiveSetWithOneEntry_works() throws Exception {
    byte[] keyMaterial = Hex.decode("000102030405060708090a0b0c0d0e0f");
    AesGcmKey key =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES128_GCM)
            .setKeyBytes(SecretBytes.copyFrom(keyMaterial, InsecureSecretKeyAccess.get()))
            .setIdRequirement(42)
            .build();
    Aead fullPrimitive = AesGcmJce.create(key);
    Keyset.Key protoKey =
        TestUtil.createKey(
            TestUtil.createAesGcmKeyData(keyMaterial),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    PrimitiveSet<Aead> pset =
        PrimitiveSet.newBuilder(Aead.class)
            .addPrimaryFullPrimitive(fullPrimitive, key, protoKey)
            .build();
    assertThat(pset.getAll()).hasSize(1);
    List<PrimitiveSet.Entry<Aead>> entries =
        pset.getPrimitive(CryptoFormat.getOutputPrefix(protoKey));
    assertThat(entries).hasSize(1);
    PrimitiveSet.Entry<Aead> entry = entries.get(0);
    assertThat(entry.getFullPrimitive()).isEqualTo(fullPrimitive);
    assertThat(entry.getIdentifier()).isEqualTo(CryptoFormat.getOutputPrefix(protoKey));
    assertThat(entry.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(entry.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(entry.getKeyId()).isEqualTo(42);
    assertThat(entry.getKeyTypeUrl()).isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmKey");
    assertThat(entry.getKey()).isEqualTo(key);
  }

  @Test
  public void testBasicFunctionality() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
            .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key2), key2)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key3), key3)
            .build();

    assertThat(pset.getAll()).hasSize(3);

    List<PrimitiveSet.Entry<Mac>> entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key1));
    assertThat(entries).hasSize(1);
    PrimitiveSet.Entry<Mac> entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.TINK_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getOutputPrefix(key1), entry.getIdentifier());
    assertEquals(1, entry.getKeyId());

    entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key2));
    assertThat(entries).hasSize(1);
    entry = entries.get(0);
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertThat(entry.getIdentifier()).isEmpty();
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());

    entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key3));
    assertThat(entries).hasSize(1);
    entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.LEGACY_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getOutputPrefix(key3), entry.getIdentifier());
    assertEquals(3, entry.getKeyId());

    entry = pset.getPrimary();
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());
  }

  @Test
  public void testAddFullPrimitive_works() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
            .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key2), key2)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key3), key3)
            .build();

    assertThat(pset.getAll()).hasSize(3);

    List<PrimitiveSet.Entry<Mac>> entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key1));
    assertThat(entries).hasSize(1);

    entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key2));
    assertThat(entries).hasSize(1);

    entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key3));
    assertThat(entries).hasSize(1);

    PrimitiveSet.Entry<Mac> entry = pset.getPrimary();
    assertThat(entry).isNotNull();
  }

  @Test
  public void testAddFullPrimitive_fullPrimitiveHandledCorrectly() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
            .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key2), key2)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key3), key3)
            .build();

    PrimitiveSet.Entry<Mac> entry = pset.getPrimitive(CryptoFormat.getOutputPrefix(key1)).get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));

    entry = pset.getPrimitive(CryptoFormat.getOutputPrefix(key2)).get(0);
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));

    entry = pset.getPrimitive(CryptoFormat.getOutputPrefix(key3)).get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));

    entry = pset.getPrimary();
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
  }

  @Test
  public void testAddFullPrimitive_keysHandledCorrectly() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
            .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key2), key2)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key3), key3)
            .build();

    PrimitiveSet.Entry<Mac> entry = pset.getPrimitive(CryptoFormat.getOutputPrefix(key1)).get(0);
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key1), entry.getIdentifier());
    assertEquals(1, entry.getKeyId());

    entry = pset.getPrimitive(CryptoFormat.getOutputPrefix(key2)).get(0);
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());

    entry = pset.getPrimitive(CryptoFormat.getOutputPrefix(key3)).get(0);
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key3), entry.getIdentifier());
    assertEquals(3, entry.getKeyId());

    entry = pset.getPrimary();
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());
  }

  @Test
  public void testAddFullPrimitive_throwsOnDoublePrimaryAdd() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    assertThrows(
        IllegalStateException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addPrimaryFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
                .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key2), key2)
                .build());
  }

  @Test
  public void testNoPrimary_getPrimaryReturnsNull() throws Exception {
    Key key =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key), key)
            .build();
    assertThat(pset.getPrimary()).isNull();
  }

  @Test
  public void testEntryGetParametersToString() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(KeyData.newBuilder().setTypeUrl("typeUrl1").build())
            .build();

    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addPrimaryFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
            .build();
    assertThat(
            pset.getPrimitive(CryptoFormat.getOutputPrefix(key1)).get(0).getParameters().toString())
        .isEqualTo("(typeUrl=typeUrl1, outputPrefixType=TINK)");
  }

  @Test
  public void getKeyWithoutParser_givesLegacyProtoKey() throws Exception {
    PrimitiveSet.Builder<Mac> builder = PrimitiveSet.newBuilder(Mac.class);
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .setKeyData(KeyData.newBuilder().setTypeUrl("typeUrl1").build())
            .build();
    builder.addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1);
    PrimitiveSet<Mac> pset = builder.build();
    com.google.crypto.tink.Key key =
        pset.getPrimitive(CryptoFormat.getOutputPrefix(key1)).get(0).getKey();

    assertThat(key).isInstanceOf(LegacyProtoKey.class);
    LegacyProtoKey legacyProtoKey = (LegacyProtoKey) key;
    assertThat(legacyProtoKey.getSerialization(InsecureSecretKeyAccess.get()).getTypeUrl())
        .isEqualTo("typeUrl1");
  }

  @Test
  public void getKeyWithParser_works() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    Key protoKey =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            /* keyId= */ 42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    byte[] prefix = CryptoFormat.getOutputPrefix(protoKey);
    PrimitiveSet.Builder<Mac> builder = PrimitiveSet.newBuilder(Mac.class);
    builder.addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(protoKey), protoKey);
    PrimitiveSet<Mac> pset = builder.build();

    com.google.crypto.tink.Key key = pset.getPrimitive(prefix).get(0).getKey();
    assertThat(key).isInstanceOf(HmacKey.class);
    HmacKey hmacKey = (HmacKey) key;
    assertThat(hmacKey.getIdRequirementOrNull()).isEqualTo(42);
  }

  @Test
  public void addPrimitiveWithInvalidKeyThatHasAParser_throws() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    com.google.crypto.tink.proto.HmacKey invalidProtoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(999)
            .setKeyValue(ByteString.copyFromUtf8("01234567890123456"))
            .setParams(HmacParams.newBuilder().setHash(HashType.UNKNOWN_HASH).setTagSize(0))
            .build();
    Key protoKey =
        TestUtil.createKey(
            TestUtil.createKeyData(
                invalidProtoHmacKey,
                "type.googleapis.com/google.crypto.tink.HmacKey",
                KeyData.KeyMaterialType.SYMMETRIC),
            /* keyId= */ 42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);

    PrimitiveSet.Builder<Mac> builder = PrimitiveSet.newBuilder(Mac.class);
    assertThrows(
        GeneralSecurityException.class,
        () -> builder.addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(protoKey), protoKey));
  }

  @Test
  public void testWithAnnotations() throws Exception {
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("name", "value").build();
    PrimitiveSet<Mac> pset = PrimitiveSet.newBuilder(Mac.class).setAnnotations(annotations).build();

    HashMap<String, String> expected = new HashMap<>();
    expected.put("name", "value");
    assertThat(pset.getAnnotations().toMap()).containsExactlyEntriesIn(expected);
  }

  @Test
  public void testGetEmptyAnnotations() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newBuilder(Mac.class).build();
    assertThat(pset.getAnnotations()).isEqualTo(MonitoringAnnotations.EMPTY);
  }

  @Test
  public void testDuplicateKeys() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    Key key4 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    Key key5 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key6 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();

    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), null, key1)
            .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key2), key2)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key3), key3)
            .addFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key4), key4)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key5), key5)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key6), key6)
            .build();

    assertThat(pset.getAll()).hasSize(3); // 3 instead of 6 because of duplicated key ids

    // tink keys
    List<PrimitiveSet.Entry<Mac>> entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key1));
    assertThat(entries).hasSize(1);
    PrimitiveSet.Entry<Mac> entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.TINK_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getOutputPrefix(key1), entry.getIdentifier());
    assertEquals(1, entry.getKeyId());

    // raw keys
    List<Integer> ids = new ArrayList<>(); // The order of the keys is an implementation detail.
    entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key2));
    assertThat(entries).hasSize(3);
    entry = entries.get(0);
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertThat(entry.getIdentifier()).isEmpty();
    ids.add(entry.getKeyId());
    entry = entries.get(1);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertThat(entry.getIdentifier()).isEmpty();
    ids.add(entry.getKeyId());
    entry = entries.get(2);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertThat(entry.getIdentifier()).isEmpty();
    ids.add(entry.getKeyId());

    assertThat(ids).containsExactly(1, 3, 3);
    // legacy keys
    entries = pset.getPrimitive(CryptoFormat.getOutputPrefix(key3));
    assertThat(entries).hasSize(2);
    entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key3), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());
    entry = entries.get(1);
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key4), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());

    entry = pset.getPrimary();
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getFullPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertThat(entry.getIdentifier()).isEmpty();
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(1, entry.getKeyId());
  }

  @Test
  public void testAddFullPrimive_withUnknownPrefixType_shouldFail() throws Exception {
    Key key1 = Key.newBuilder().setKeyId(1).setStatus(KeyStatusType.ENABLED).build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addPrimaryFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
                .build());
  }

  @Test
  public void testAddFullPrimive_withDisabledKey_shouldFail() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.DISABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
                .build());
    assertThrows(
        GeneralSecurityException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addPrimaryFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
                .build());
  }

  @Test
  public void testAddFullPrimive_withNullPrimitive_throwsNullPointerException() throws Exception {
    Key key =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    assertThrows(
        NullPointerException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addFullPrimitive(null, getKeyFromProtoKey(key), key));

    assertThrows(
        NullPointerException.class,
        () ->
            PrimitiveSet.newBuilder(Mac.class)
                .addPrimaryFullPrimitive(null, getKeyFromProtoKey(key), key));
  }

  @Test
  public void testPrefixIsUnique() throws Exception {
    Key key1 =
        Key.newBuilder()
            .setKeyId(0xffffffff)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(0xffffffdf)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key3 =
        Key.newBuilder()
            .setKeyId(0xffffffef)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();

    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key1), key1)
            .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key2), key2)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key3), key3)
            .build();

    assertThat(pset.getAll()).hasSize(3);
    assertThat(pset.getPrimitive(Hex.decode("01ffffffff"))).hasSize(1);
    assertThat(pset.getPrimitive(Hex.decode("01ffffffef"))).isEmpty();
    assertThat(pset.getPrimitive(Hex.decode("00ffffffff"))).isEmpty();
    assertThat(pset.getPrimitive(Hex.decode("00ffffffef"))).hasSize(1);
  }

  @Test
  public void getAllInKeysetOrder_works() throws Exception {
    Key key0 =
        Key.newBuilder()
            .setKeyId(0xffffffff)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    Key key1 =
        Key.newBuilder()
            .setKeyId(0xffffffdf)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    Key key2 =
        Key.newBuilder()
            .setKeyId(0xffffffef)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    PrimitiveSet<Mac> pset =
        PrimitiveSet.newBuilder(Mac.class)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key0), key0)
            .addPrimaryFullPrimitive(new DummyMac2(), getKeyFromProtoKey(key1), key1)
            .addFullPrimitive(new DummyMac1(), getKeyFromProtoKey(key2), key2)
            .build();

    List<PrimitiveSet.Entry<Mac>> entries = pset.getAllInKeysetOrder();
    assertThat(entries).hasSize(3);
    assertThat(entries.get(0).getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(entries.get(1).getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(entries.get(2).getOutputPrefixType()).isEqualTo(OutputPrefixType.LEGACY);
  }
}
