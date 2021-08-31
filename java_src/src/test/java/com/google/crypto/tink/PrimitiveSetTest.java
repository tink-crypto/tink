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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
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

  @Test
  public void testBasicFunctionality() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet(Mac.class);
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    pset.addPrimitive(new DummyMac1(), key1);
    Key key2 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    pset.setPrimary(pset.addPrimitive(new DummyMac2(), key2));
    Key key3 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    pset.addPrimitive(new DummyMac1(), key3);

    assertThat(pset.getAll()).hasSize(3);

    List<PrimitiveSet.Entry<Mac>> entries = pset.getPrimitive(key1);
    assertThat(entries).hasSize(1);
    PrimitiveSet.Entry<Mac> entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.TINK_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getOutputPrefix(key1), entry.getIdentifier());
    assertEquals(entry.getKeyId(), 1);

    entries = pset.getPrimitive(key2);
    assertThat(entries).hasSize(1);
    entry = entries.get(0);
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertThat(entry.getIdentifier()).isEmpty();
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());

    entries = pset.getPrimitive(key3);
    assertThat(entries).hasSize(1);
    entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.LEGACY_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getOutputPrefix(key3), entry.getIdentifier());
    assertEquals(entry.getKeyId(), 3);

    entry = pset.getPrimary();
    assertEquals(
        DummyMac2.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());
  }

  @Test
  public void testDuplicateKeys() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet(Mac.class);
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    pset.addPrimitive(new DummyMac1(), key1);

    Key key2 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    pset.setPrimary(pset.addPrimitive(new DummyMac2(), key2));

    Key key3 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    pset.addPrimitive(new DummyMac1(), key3);

    Key key4 =
        Key.newBuilder()
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    pset.addPrimitive(new DummyMac2(), key4);

    Key key5 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    pset.addPrimitive(new DummyMac1(), key5);

    Key key6 =
        Key.newBuilder()
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    pset.addPrimitive(new DummyMac1(), key6);

    assertEquals(3, pset.getAll().size()); // 3 instead of 6 because of duplicated key ids

    // tink keys
    List<PrimitiveSet.Entry<Mac>> entries = pset.getPrimitive(key1);
    assertEquals(1, entries.size());
    PrimitiveSet.Entry<Mac> entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.TINK_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getOutputPrefix(key1), entry.getIdentifier());
    assertEquals(1, entry.getKeyId());

    // raw keys
    List<Integer> ids = new ArrayList<>(); // The order of the keys is an implementation detail.
    entries = pset.getPrimitive(key2);
    assertEquals(3, entries.size());
    entry = entries.get(0);
    assertEquals(
        DummyMac2.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    ids.add(entry.getKeyId());
    entry = entries.get(1);
    assertEquals(
        DummyMac1.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    ids.add(entry.getKeyId());
    entry = entries.get(2);
    assertEquals(
        DummyMac1.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    ids.add(entry.getKeyId());

    assertThat(ids).containsExactly(1, 3, 3);
    // legacy keys
    entries = pset.getPrimitive(key3);
    assertEquals(2, entries.size());
    entry = entries.get(0);
    assertEquals(
        DummyMac1.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key3), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());
    entry = entries.get(1);
    assertEquals(
        DummyMac2.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getOutputPrefix(key4), entry.getIdentifier());
    assertEquals(2, entry.getKeyId());

    entry = pset.getPrimary();
    assertEquals(
        DummyMac2.class.getSimpleName(), new String(entry.getPrimitive().computeMac(null), UTF_8));
    assertEquals(KeyStatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    assertArrayEquals(CryptoFormat.getOutputPrefix(key2), entry.getIdentifier());
    assertEquals(1, entry.getKeyId());
  }

  @Test
  public void testAddPrimive_withUnknownPrefixType_shouldFail() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet(Mac.class);
    Key key1 = Key.newBuilder().setKeyId(1).setStatus(KeyStatusType.ENABLED).build();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> pset.addPrimitive(new DummyMac1(), key1));
    assertExceptionContains(e, "unknown output prefix type");
  }

  @Test
  public void testAddPrimive_withDisabledKey_shouldFail() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet(Mac.class);
    Key key1 =
        Key.newBuilder()
            .setKeyId(1)
            .setStatus(KeyStatusType.DISABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> pset.addPrimitive(new DummyMac1(), key1));
    assertExceptionContains(e, "only ENABLED key is allowed");
  }

  @Test
  public void testPrefix_isUnique() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet(Mac.class);
    Key key1 =
        Key.newBuilder()
            .setKeyId(0xffffffff)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    pset.addPrimitive(new DummyMac1(), key1);
    Key key2 =
        Key.newBuilder()
            .setKeyId(0xffffffdf)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.RAW)
            .build();
    pset.setPrimary(pset.addPrimitive(new DummyMac2(), key2));
    Key key3 =
        Key.newBuilder()
            .setKeyId(0xffffffef)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.LEGACY)
            .build();
    pset.addPrimitive(new DummyMac1(), key3);

    assertThat(pset.getAll()).hasSize(3);

    assertThat(pset.getPrimitive(Hex.decode("01ffffffff"))).hasSize(1);
    assertThat(pset.getPrimitive(Hex.decode("01ffffffef"))).isEmpty();
    assertThat(pset.getPrimitive(Hex.decode("00ffffffff"))).isEmpty();
    assertThat(pset.getPrimitive(Hex.decode("00ffffffef"))).hasSize(1);
  }
}
