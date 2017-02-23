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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.Keyset.KeyStatus;
import com.google.protobuf.Any;
import java.security.GeneralSecurityException;
import java.util.concurrent.Future;
import org.junit.Test;

/**
 * Tests for Registry.
 */
public class RegistryTest {

  private class DummyMac implements Mac {
    private final String label;
    public DummyMac(String label) {
      this.label = label;
    }
    @Override
    public byte[] computeMac(byte[] data) throws GeneralSecurityException {
      return label.getBytes();
    }
    @Override
    public boolean verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
      return true;
    }
  }

  private class DummyAead implements Aead {
    private final String label;
    public DummyAead(String label) {
      this.label = label;
    }
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
      return label.getBytes();
    }
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
      return label.getBytes();
    }
    @Override
    public Future<byte[]> asyncEncrypt(byte[] plaintext, byte[] aad)
        throws GeneralSecurityException {
      return null;
    }
    @Override
    public Future<byte[]> asyncDecrypt(byte[] ciphertext, byte[] aad)
        throws GeneralSecurityException {
      return null;
    }
  }

  private class Mac1KeyManager implements KeyManager<Mac> {
    public Mac1KeyManager() {}

    @Override
    public Mac getPrimitive(Any proto) throws GeneralSecurityException {
      return new DummyMac(this.getClass().getSimpleName());
    }
    @Override
    public Any newKey(KeyFormat format) throws GeneralSecurityException {
      return Any.newBuilder().setTypeUrl(this.getClass().getSimpleName()).build();
    }
    @Override
    public boolean doesSupport(String typeUrl) {
      return typeUrl == this.getClass().getSimpleName();
    }
  }

  private class Mac2KeyManager implements KeyManager<Mac> {
    public Mac2KeyManager() {}

    @Override
    public Mac getPrimitive(Any proto) throws GeneralSecurityException {
      return new DummyMac(this.getClass().getSimpleName());
    }
    @Override
    public Any newKey(KeyFormat format) throws GeneralSecurityException {
      return Any.newBuilder().setTypeUrl(this.getClass().getSimpleName()).build();
    }
    @Override
    public boolean doesSupport(String typeUrl) {
      return typeUrl == this.getClass().getSimpleName();
    }
  }

  private class AeadKeyManager implements KeyManager<Aead> {
    public AeadKeyManager() {}

    @Override
    public Aead getPrimitive(Any proto) throws GeneralSecurityException {
      return new DummyAead(this.getClass().getSimpleName());
    }
    @Override
    public Any newKey(KeyFormat format) throws GeneralSecurityException {
      return Any.newBuilder().setTypeUrl(this.getClass().getSimpleName()).build();
    }
    @Override
    public boolean doesSupport(String typeUrl) {
      return typeUrl == this.getClass().getSimpleName();
    }
  }

  @Test
  public void testKeyManagerRegistration() throws Exception {
    Registry registry = new Registry();

    String mac1TypeUrl = Mac1KeyManager.class.getSimpleName();
    String mac2TypeUrl = Mac2KeyManager.class.getSimpleName();
    String aeadTypeUrl = AeadKeyManager.class.getSimpleName();

    // Register some key managers.
    registry.registerKeyManager(mac1TypeUrl, new Mac1KeyManager());
    registry.registerKeyManager(mac2TypeUrl, new Mac2KeyManager());
    registry.registerKeyManager(aeadTypeUrl, new AeadKeyManager());

    // Retrieve some key managers.
    KeyManager<Mac> mac1Manager = registry.getKeyManager(mac1TypeUrl);
    KeyManager<Mac> mac2Manager = registry.getKeyManager(mac2TypeUrl);
    assertEquals(Mac1KeyManager.class, mac1Manager.getClass());
    assertEquals(Mac2KeyManager.class, mac2Manager.getClass());
    String computedMac = new String(mac1Manager.getPrimitive(null).computeMac(null));
    assertEquals(Mac1KeyManager.class.getSimpleName(), computedMac);
    computedMac = new String(mac2Manager.getPrimitive(null).computeMac(null));
    assertEquals(Mac2KeyManager.class.getSimpleName(), computedMac);

    KeyManager<Aead> aeadManager = registry.getKeyManager(aeadTypeUrl);
    assertEquals(AeadKeyManager.class, aeadManager.getClass());
    Aead aead = aeadManager.getPrimitive(null);
    String ciphertext = new String(aead.encrypt("plaintext".getBytes(), null));
    assertEquals(AeadKeyManager.class.getSimpleName(), ciphertext);
    // TODO(przydatek): add tests when the primitive of KeyManager does not match key type.

    String badTypeUrl = "bad type URL";
    try {
      KeyManager<Mac> macManager = registry.getKeyManager(badTypeUrl);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("Unsupported"));
      assertTrue(e.toString().contains(badTypeUrl));
    }
  }

  @Test
  public void testKeyAndPrimitiveCreation() throws Exception {
    Registry registry = new Registry();

    String mac1TypeUrl = Mac1KeyManager.class.getSimpleName();
    String mac2TypeUrl = Mac2KeyManager.class.getSimpleName();
    String aeadTypeUrl = AeadKeyManager.class.getSimpleName();

    // Register some key managers.
    registry.registerKeyManager(mac1TypeUrl, new Mac1KeyManager());
    registry.registerKeyManager(mac2TypeUrl, new Mac2KeyManager());
    registry.registerKeyManager(aeadTypeUrl, new AeadKeyManager());

    // Create some keys and primitives.
    KeyFormat format = KeyFormat.newBuilder().setKeyType(mac2TypeUrl).build();
    Any key = registry.newKey(format);
    assertEquals(mac2TypeUrl, key.getTypeUrl());
    Mac mac = registry.getPrimitive(key);
    String computedMac = new String(mac.computeMac(null));
    assertEquals(mac2TypeUrl, computedMac);

    format = KeyFormat.newBuilder().setKeyType(aeadTypeUrl).build();
    key = registry.newKey(format);
    assertEquals(aeadTypeUrl, key.getTypeUrl());
    Aead aead = registry.getPrimitive(key);
    String ciphertext = new String(aead.encrypt(null, null));
    assertEquals(aeadTypeUrl, ciphertext);

    // Create a keyset, and get a PrimitiveSet.
    KeyFormat format1 = KeyFormat.newBuilder().setKeyType(mac1TypeUrl).build();
    KeyFormat format2 = KeyFormat.newBuilder().setKeyType(mac2TypeUrl).build();
    Any key1 = registry.newKey(format1);
    Any key2 = registry.newKey(format1);
    Any key3 = registry.newKey(format2);
    KeysetHandle keysetHandle = new KeysetHandle() {
        public byte[] getSource() {
          return "keyset source".getBytes();
        }
        public Keyset getKeyset() {
          return Keyset.newBuilder()
              .addKey(Keyset.Key.newBuilder()
                  .setKeyData(key1).setKeyId(1).setStatus(KeyStatus.ENABLED).build())
              .addKey(Keyset.Key.newBuilder()
                  .setKeyData(key2).setKeyId(2).setStatus(KeyStatus.ENABLED).build())
              .addKey(Keyset.Key.newBuilder()
                  .setKeyData(key3).setKeyId(3).setStatus(KeyStatus.ENABLED).build())
              .setPrimaryKeyId(2)
              .build();
        }
      };
    PrimitiveSet<Mac> macSet = registry.getPrimitives(keysetHandle);
    assertEquals(3, macSet.size());
    computedMac = new String(macSet.getPrimary().getPrimitive().computeMac(null));
    assertEquals(mac1TypeUrl, computedMac);

    // Try a keyset with some keys non-ENABLED.
    keysetHandle = new KeysetHandle() {
        public byte[] getSource() {
          return "keyset source".getBytes();
        }
        public Keyset getKeyset() {
          return Keyset.newBuilder()
              .addKey(Keyset.Key.newBuilder()
                  .setKeyData(key1).setKeyId(1).setStatus(KeyStatus.DESTROYED).build())
              .addKey(Keyset.Key.newBuilder()
                  .setKeyData(key2).setKeyId(2).setStatus(KeyStatus.DISABLED).build())
              .addKey(Keyset.Key.newBuilder()
                  .setKeyData(key3).setKeyId(3).setStatus(KeyStatus.ENABLED).build())
              .setPrimaryKeyId(3)
              .build();
        }
      };
    macSet = registry.getPrimitives(keysetHandle);
    assertEquals(1, macSet.size());
    computedMac = new String(macSet.getPrimary().getPrimitive().computeMac(null));
    assertEquals(mac2TypeUrl, computedMac);
  }


  @Test
  public void testRegistryCollisions() throws Exception {
    Registry registry = new Registry();
    String mac1TypeUrl = Mac1KeyManager.class.getSimpleName();
    String mac2TypeUrl = Mac2KeyManager.class.getSimpleName();

    try {
      registry.registerKeyManager(mac1TypeUrl, null);
      fail("Expected NullPointerException.");
    } catch (NullPointerException e) {
      assertTrue(e.toString().contains("must be non-null"));
    }

    registry.registerKeyManager(mac1TypeUrl, new Mac1KeyManager());
    registry.registerKeyManager(mac2TypeUrl, new Mac2KeyManager());

    try {
      registry.registerKeyManager(mac1TypeUrl, new Mac1KeyManager());
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains(mac1TypeUrl));
      assertTrue(e.toString().contains("already registered"));
    }
  }

  // TODO(przydatek): Add more tests for creation of PrimitiveSets.
}
