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

package com.google.cloud.crypto.tink;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.TinkProto.Keyset.Key;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.PrefixType;
import com.google.cloud.crypto.tink.TinkProto.Keyset.Key.StatusType;
import java.util.List;
import java.security.GeneralSecurityException;
import org.junit.Test;

/**
 * Tests for PrimitiveSet.
 */
public class PrimitiveSetTest {
  private class DummyMac1 implements Mac {
    public DummyMac1() {}
    @Override
    public byte[] computeMac(byte[] data) throws GeneralSecurityException {
      return this.getClass().getSimpleName().getBytes();
    }
    @Override
    public boolean verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
      return true;
    }
  }

  private class DummyMac2 implements Mac {
    public DummyMac2() {}
    @Override
    public byte[] computeMac(byte[] data) throws GeneralSecurityException {
      return this.getClass().getSimpleName().getBytes();
    }
    @Override
    public boolean verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
      return true;
    }
  }

  @Test
  public void testBasicFunctionality() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet();
    Key key1 = Key.newBuilder()
        .setKeyId(1)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.TINK)
        .build();
    pset.addPrimitive(new DummyMac1(), key1);
    Key key2 = Key.newBuilder()
        .setKeyId(2)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.RAW)
        .build();
    pset.setPrimary(pset.addPrimitive(new DummyMac2(), key2));
    Key key3 = Key.newBuilder()
        .setKeyId(3)
        .setStatus(StatusType.DISABLED)
        .setPrefixType(PrefixType.LEGACY)
        .build();
    pset.addPrimitive(new DummyMac1(), key3);

    List<PrimitiveSet<Mac>.Entry<Mac>> entries = pset.getPrimitive(key1);
    assertEquals(1, entries.size());
    PrimitiveSet<Mac>.Entry<Mac> entry = entries.get(0);
    assertEquals(DummyMac1.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.TINK_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getPrefix(key1), entry.getIdentifier());

    entries = pset.getPrimitive(key2);
    assertEquals(1, entries.size());
    entry = entries.get(0);
    assertEquals(DummyMac2.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    assertArrayEquals(CryptoFormat.getPrefix(key2), entry.getIdentifier());

    entries = pset.getPrimitive(key3);
    assertEquals(1, entries.size());
    entry = entries.get(0);
    assertEquals(DummyMac1.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.DISABLED, entry.getStatus());
    assertEquals(CryptoFormat.LEGACY_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getPrefix(key3), entry.getIdentifier());

    entry = pset.getPrimary();
    assertEquals(DummyMac2.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getPrefix(key2), entry.getIdentifier());
  }

  @Test
  public void testDuplicateKeys() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet();
    Key key1 = Key.newBuilder()
        .setKeyId(1)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.TINK)
        .build();
    pset.addPrimitive(new DummyMac1(), key1);

    Key key2 = Key.newBuilder()
        .setKeyId(1)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.RAW)
        .build();
    pset.setPrimary(pset.addPrimitive(new DummyMac2(), key2));

    Key key3 = Key.newBuilder()
        .setKeyId(2)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.LEGACY)
        .build();
    pset.addPrimitive(new DummyMac1(), key3);

    Key key4 = Key.newBuilder()
        .setKeyId(2)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.LEGACY)
        .build();
    pset.addPrimitive(new DummyMac2(), key4);

    Key key5 = Key.newBuilder()
        .setKeyId(3)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.RAW)
        .build();
    pset.addPrimitive(new DummyMac1(), key5);

    Key key6 = Key.newBuilder()
        .setKeyId(3)
        .setStatus(StatusType.ENABLED)
        .setPrefixType(PrefixType.RAW)
        .build();
    pset.addPrimitive(new DummyMac1(), key6);

    // tink keys
    List<PrimitiveSet<Mac>.Entry<Mac>> entries = pset.getPrimitive(key1);
    assertEquals(1, entries.size());
    PrimitiveSet<Mac>.Entry<Mac> entry = entries.get(0);
    assertEquals(DummyMac1.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertEquals(CryptoFormat.TINK_START_BYTE, entry.getIdentifier()[0]);
    assertArrayEquals(CryptoFormat.getPrefix(key1), entry.getIdentifier());

    // raw keys
    entries = pset.getPrimitive(key2);
    assertEquals(3, entries.size());
    entry = entries.get(0);
    assertEquals(DummyMac2.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    entry = entries.get(1);
    assertEquals(DummyMac1.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    entry = entries.get(2);
    assertEquals(DummyMac1.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);

    // legacy keys
    entries = pset.getPrimitive(key3);
    assertEquals(2, entries.size());
    entry = entries.get(0);
    assertEquals(DummyMac1.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getPrefix(key3), entry.getIdentifier());
    entry = entries.get(1);
    assertEquals(DummyMac2.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertArrayEquals(CryptoFormat.getPrefix(key4), entry.getIdentifier());

    entry = pset.getPrimary();
    assertEquals(DummyMac2.class.getSimpleName(),
        new String(entry.getPrimitive().computeMac(null)));
    assertEquals(StatusType.ENABLED, entry.getStatus());
    assertEquals(0, entry.getIdentifier().length);
    assertArrayEquals(CryptoFormat.getPrefix(key2), entry.getIdentifier());
  }

  @Test
  public void testAddInvalidKey() throws Exception {
    PrimitiveSet<Mac> pset = PrimitiveSet.newPrimitiveSet();
    Key key1 = Key.newBuilder()
        .setKeyId(1)
        .setStatus(StatusType.ENABLED)
        .build();
    try {
      pset.addPrimitive(new DummyMac1(), key1);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("invalid key"));
    }
  }
}
