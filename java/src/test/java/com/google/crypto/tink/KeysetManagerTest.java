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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for KeysetManager.
 */
@RunWith(JUnit4.class)
public class KeysetManagerTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
  }

  private Key createEnabledKey(int keyId) {
    return Key.newBuilder()
        .setKeyId(keyId)
        .setStatus(KeyStatusType.ENABLED)
        .build();
  }

  private Key createDisabledKey(int keyId) {
    return Key.newBuilder()
        .setKeyId(keyId)
        .setStatus(KeyStatusType.DISABLED)
        .build();
  }

  private Key createDestroyedKey(int keyId) {
    return Key.newBuilder()
        .setKeyId(keyId)
        .setStatus(KeyStatusType.DESTROYED)
        .build();
  }

  private Key createUnknownStatusKey(int keyId) {
    return Key.newBuilder()
        .setKeyId(keyId)
        .setStatus(KeyStatusType.UNKNOWN_STATUS)
        .build();
  }

  @Test
  public void testEnable_shouldEnableKey() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(createDisabledKey(keyId)));
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).enable(keyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(keyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testEnable_unknownStatus_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(createUnknownStatusKey(keyId)));

    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).enable(keyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot enable");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testEnable_keyDestroyed_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(createDestroyedKey(keyId)));

    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).enable(keyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot enable");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testEnable_keyNotFound_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(createDisabledKey(keyId)));

    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).enable(keyId + 1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("key not found");
    }
  }

  @Test
  public void testSetPrimary_shouldSetPrimary() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(newPrimaryKeyId)));
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle)
            .setPrimary(newPrimaryKeyId)
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(newPrimaryKeyId);
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testSetPrimary_keyNotFound_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).setPrimary(44);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("key not found");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testSetPrimary_keyDisabled_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createDisabledKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).setPrimary(newPrimaryKeyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testSetPrimary_keyDestroyed_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createDestroyedKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).setPrimary(newPrimaryKeyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testSetPrimary_keyUnknownStatus_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createUnknownStatusKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).setPrimary(newPrimaryKeyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
    }
  }

  // Same tests as for setPrimary() for the deprecated promote(), which should be equivalent.
  @Test
  public void testPromote_shouldPromote() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(newPrimaryKeyId)));
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle)
            .promote(newPrimaryKeyId)
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(newPrimaryKeyId);
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testPromote_keyNotFound_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).promote(44);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("key not found");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testPromote_keyDisabled_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createDisabledKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).promote(newPrimaryKeyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testPromote_keyDestroyed_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createDestroyedKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).promote(newPrimaryKeyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testPromote_keyUnknownStatus_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createUnknownStatusKey(newPrimaryKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).promote(newPrimaryKeyId);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
    }
  }

  @Test
  public void testDisable_shouldDisableKey() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(otherKeyId)));
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).disable(otherKeyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(primaryKeyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getKeyId()).isEqualTo(otherKeyId);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.DISABLED);
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDisable_keyIsPrimary_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(otherKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).disable(primaryKeyId).getKeysetHandle().getKeyset();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot disable the primary key");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDisable_keyDestroyed_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createDestroyedKey(otherKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).disable(otherKeyId).getKeysetHandle().getKeyset();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot disable key");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDisable_keyNotFound_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(createDisabledKey(keyId)));

    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).disable(keyId + 1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("key not found");
    }
  }

  @Test
  public void testDestroy_shouldDestroyKey() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(otherKeyId)));
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).destroy(otherKeyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(primaryKeyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getKeyId()).isEqualTo(otherKeyId);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.DESTROYED);
    assertThat(keyset.getKey(1).hasKeyData()).isFalse();
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDestroy_keyIsPrimary_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(otherKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).destroy(primaryKeyId).getKeysetHandle().getKeyset();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot destroy the primary key");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDestroy_keyUnknownStatus_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createUnknownStatusKey(otherKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).destroy(otherKeyId).getKeysetHandle().getKeyset();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot destroy key");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDestroy_keyNotFound_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(createDisabledKey(keyId)));

    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).destroy(keyId + 1);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("key not found");
    }
  }

  @Test
  public void testDelete_shouldDeleteKey() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(otherKeyId)));
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).delete(otherKeyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(primaryKeyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDelete_keyIsPrimary_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(otherKeyId)));
    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).delete(primaryKeyId).getKeysetHandle().getKeyset();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("cannot delete the primary key");
    }
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testDelete_keyNotFound_shouldThrowException() throws Exception {
    int keyId1 = 42;
    final int keyId2 = 43;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(keyId1),
            createEnabledKey(keyId2)));

    try {
      // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
      KeysetManager.withKeysetHandle(handle).delete(44);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("key not found");
    }
  }

  @Test
  public void testRotate_shouldAddNewKeyAndSetPrimaryKeyId() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    // TODO(b/145386688): This access should be guarded by 'KeysetManager.withEmptyKeyset()', which
    // is not currently held
    Keyset keyset = KeysetManager.withEmptyKeyset().rotate(template).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyset.getKey(0).getKeyId());
    TestUtil.assertHmacKey(template, keyset.getKey(0));
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testRotate_bogusKeyTemplate_shouldThrowException() throws Exception {
    KeyTemplate bogus = TestUtil.createKeyTemplateWithNonExistingTypeUrl();

    try {
      // TODO(b/145386688): This access should be guarded by 'KeysetManager.withEmptyKeyset()',
      // which is not currently held
      KeysetManager.withEmptyKeyset().rotate(bogus);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      TestUtil.assertExceptionContains(e, "No key manager found for key type");
    }
  }

  @Test
  public void testRotate_existingKeyset_shouldAddNewKeyAndSetPrimaryKeyId() throws Exception {
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    // TODO(b/145386688): This access should be guarded by 'KeysetManager.withEmptyKeyset()', which
    // is not currently held
    KeysetHandle existing =
        KeysetManager.withEmptyKeyset()
            .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
            .getKeysetHandle();
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(existing)
            .rotate(MacKeyTemplates.HMAC_SHA256_256BITTAG)
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyset.getKey(1).getKeyId());
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, keyset.getKey(0));
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_256BITTAG, keyset.getKey(1));
  }

  @Test
  public void testAdd_shouldAddNewKey() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    // TODO(b/145386688): This access should be guarded by 'KeysetManager.withEmptyKeyset()', which
    // is not currently held
    Keyset keyset = KeysetManager.withEmptyKeyset().add(template).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(0);
    TestUtil.assertHmacKey(template, keyset.getKey(0));
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testAdd_bogusKeyTemplate_shouldThrowException() throws Exception {
    KeyTemplate bogus = TestUtil.createKeyTemplateWithNonExistingTypeUrl();

    try {
      // TODO(b/145386688): This access should be guarded by 'KeysetManager.withEmptyKeyset()',
      // which is not currently held
      KeysetManager.withEmptyKeyset().add(bogus);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      TestUtil.assertExceptionContains(e, "No key manager found for key type");
    }
  }

  @Test
  public void testAdd_existingKeySet_shouldAddNewKey() throws Exception {
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    // TODO(b/145386688): This access should be guarded by 'KeysetManager.withEmptyKeyset()', which
    // is not currently held
    KeysetHandle existing =
        KeysetManager.withEmptyKeyset()
            .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
            .getKeysetHandle();
    int existingPrimaryKeyId = existing.getKeyset().getPrimaryKeyId();
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'this', which could not be resolved
    Keyset keyset =
        KeysetManager.withKeysetHandle(existing)
            .add(MacKeyTemplates.HMAC_SHA256_256BITTAG)
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(existingPrimaryKeyId);
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, keyset.getKey(0));
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_256BITTAG, keyset.getKey(1));
  }

  @Test
  @SuppressWarnings("GuardedBy")
  public void testAddNewKey_onePrimary() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    int keyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyId);
    TestUtil.assertHmacKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, keyset.getKey(0));
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testAddNewKey_onePrimaryAnotherPrimary() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    int primaryKeyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(primaryKeyId);
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testAddNewKey_primaryThenNonPrimary() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    int primaryKeyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, false);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(primaryKeyId);
  }

  @SuppressWarnings("GuardedBy")
  @Test
  public void testAddNewKey_addThenDestroy() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    int secondaryKeyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, false);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    keysetManager.destroy(secondaryKeyId);
    // TODO(b/145386688): This access should be guarded by 'keysetManager', which is not currently
    // held
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(2);
    // One of the two keys is destroyed and doesn't have keyData anymore.
    assertTrue(!keyset.getKey(0).hasKeyData() || !keyset.getKey(1).hasKeyData());
  }

  @SuppressWarnings("GuardedBy")
  private void manipulateKeyset(KeysetManager manager) {
    try {
      KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
      // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
      manager.rotate(template).add(template).rotate(template).add(template);
    } catch (GeneralSecurityException e) {
      fail("should not throw exception: " + e);
    }
  }

  @Test
  public void testThreadSafety_manipulateKeyset_shouldWork() throws Exception {
    final KeysetManager manager = KeysetManager.withEmptyKeyset();
    Thread thread1 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            manipulateKeyset(manager);
          }
        });
    Thread thread2 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            manipulateKeyset(manager);
          }
        });
    Thread thread3 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            manipulateKeyset(manager);
          }
        });
    thread1.start();
    thread2.start();
    thread3.start();

    // Wait until all threads finished.
    thread1.join();
    thread2.join();
    thread3.join();
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(12);
  }

  @SuppressWarnings("GuardedBy")
  private void enableSetPrimaryKey(KeysetManager manager, int keyId) {
    try {
      // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
      manager.enable(keyId).setPrimary(keyId);
    } catch (GeneralSecurityException e) {
      fail("should not throw exception: " + e);
    }
  }

  @Test
  public void testThreadSafety_enableSetPrimaryKey_shouldWork() throws Exception {
    final int primaryKeyId = 42;
    final int keyId2 = 43;
    final int keyId3 = 44;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(keyId2),
            createDisabledKey(keyId3)));
    final KeysetManager manager = KeysetManager.withKeysetHandle(handle);

    Thread thread1 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            enableSetPrimaryKey(manager, primaryKeyId);
          }
        });
    Thread thread2 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            enableSetPrimaryKey(manager, keyId2);
          }
        });
    Thread thread3 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            enableSetPrimaryKey(manager, keyId3);
          }
        });
    thread1.start();
    thread2.start();
    thread3.start();

    // Wait until all threads finished.
    thread1.join();
    thread2.join();
    thread3.join();
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(3);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(2).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  @SuppressWarnings("GuardedBy")
  private void disableEnableSetPrimaryKey(KeysetManager manager, int keyId) {
    try {
      // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
      manager.disable(keyId).enable(keyId).setPrimary(keyId);
    } catch (GeneralSecurityException e) {
      fail("should not throw exception: " + e);
    }
  }

  @Test
  public void testThreadSafety_disableEnableSetPrimaryKey_shouldWork() throws Exception {
    final int primaryKeyId = 42;
    final int keyId2 = 43;
    final int keyId3 = 44;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(keyId2),
            createDisabledKey(keyId3)));
    final KeysetManager manager = KeysetManager.withKeysetHandle(handle);

    Thread thread2 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            disableEnableSetPrimaryKey(manager, keyId2);
          }
        });
    Thread thread3 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            disableEnableSetPrimaryKey(manager, keyId3);
          }
        });
    thread2.start();
    thread3.start();

    // Wait until all threads finished.
    thread2.join();
    thread3.join();
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(3);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(2).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  @SuppressWarnings("GuardedBy")
  private void enableDisableDeleteKey(KeysetManager manager, int keyId) {
    try {
      // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
      manager.enable(keyId).disable(keyId).delete(keyId);
    } catch (GeneralSecurityException e) {
      fail("should not throw exception: " + e);
    }
  }

  @Test
  public void testThreadSafety_enableDisableDeleteKey_shouldWork() throws Exception {
    final int primaryKeyId = 42;
    final int keyId2 = 43;
    final int keyId3 = 44;
    KeysetHandle handle = KeysetHandle.fromKeyset(
        TestUtil.createKeyset(
            createEnabledKey(primaryKeyId),
            createEnabledKey(keyId2),
            createDisabledKey(keyId3)));
    final KeysetManager manager = KeysetManager.withKeysetHandle(handle);

    Thread thread2 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            enableDisableDeleteKey(manager, keyId2);
          }
        });
    Thread thread3 = new Thread(
        new Runnable() {
          @Override
          public void run() {
            enableDisableDeleteKey(manager, keyId3);
          }
        });
    thread2.start();
    thread3.start();

    // Wait until all threads finished.
    thread2.join();
    thread3.join();
    @SuppressWarnings("GuardedBy")
    // TODO(b/145386688): This access should be guarded by 'manager', which is not currently held
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(keyset.getPrimaryKeyId());
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }
}
