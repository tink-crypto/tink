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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.common.truth.Expect;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.SecretKeyAccess;
import com.google.crypto.tink.tinkkey.TinkKey;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeysetManager. */
@RunWith(JUnit4.class)
public class KeysetManagerTest {

  @Rule public final Expect expect = Expect.create();

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
  }

  private Key createEnabledKey(int keyId) {
    return Key.newBuilder().setKeyId(keyId).setStatus(KeyStatusType.ENABLED).build();
  }

  private Key createDisabledKey(int keyId) {
    return Key.newBuilder().setKeyId(keyId).setStatus(KeyStatusType.DISABLED).build();
  }

  private Key createDestroyedKey(int keyId) {
    return Key.newBuilder().setKeyId(keyId).setStatus(KeyStatusType.DESTROYED).build();
  }

  private Key createUnknownStatusKey(int keyId) {
    return Key.newBuilder().setKeyId(keyId).setStatus(KeyStatusType.UNKNOWN_STATUS).build();
  }

  @Test
  public void testEnable_shouldEnableKey() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(createDisabledKey(keyId)));
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).enable(keyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(keyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  @Test
  public void testEnable_unknownStatus_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(TestUtil.createKeyset(createUnknownStatusKey(keyId)));

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).enable(keyId));
    assertThat(e.toString()).contains("cannot enable");
  }

  @Test
  public void testEnable_keyDestroyed_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(createDestroyedKey(keyId)));

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).enable(keyId));
    assertThat(e.toString()).contains("cannot enable");
  }

  @Test
  public void testEnable_keyNotFound_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(createDisabledKey(keyId)));

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).enable(keyId + 1));
    assertThat(e.toString()).contains("key not found");
  }

  @Test
  public void testSetPrimary_shouldSetPrimary() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createEnabledKey(newPrimaryKeyId)));
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle)
            .setPrimary(newPrimaryKeyId)
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(newPrimaryKeyId);
  }

  @Test
  public void testSetPrimary_keyNotFound_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createEnabledKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).setPrimary(44));
    assertThat(e.toString()).contains("key not found");
  }

  @Test
  public void testSetPrimary_keyDisabled_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createDisabledKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).setPrimary(newPrimaryKeyId));
    assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
  }

  @Test
  public void testSetPrimary_keyDestroyed_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createDestroyedKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).setPrimary(newPrimaryKeyId));
    assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
  }

  @Test
  public void testSetPrimary_keyUnknownStatus_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createUnknownStatusKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).setPrimary(newPrimaryKeyId));
    assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
  }

  // Same tests as for setPrimary() for the deprecated promote(), which should be equivalent.
  @Test
  public void testPromote_shouldPromote() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createEnabledKey(newPrimaryKeyId)));
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle)
            .promote(newPrimaryKeyId)
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(newPrimaryKeyId);
  }

  @Test
  public void testPromote_keyNotFound_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createEnabledKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).promote(44));
    assertThat(e.toString()).contains("key not found");
  }

  @Test
  public void testPromote_keyDisabled_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createDisabledKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).promote(newPrimaryKeyId));
    assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
  }

  @Test
  public void testPromote_keyDestroyed_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createDestroyedKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).promote(newPrimaryKeyId));
    assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
  }

  @Test
  public void testPromote_keyUnknownStatus_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int newPrimaryKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createUnknownStatusKey(newPrimaryKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).promote(newPrimaryKeyId));
    assertThat(e.toString()).contains("cannot set key as primary because it's not enabled");
  }

  @Test
  public void testDisable_shouldDisableKey() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(primaryKeyId), createEnabledKey(otherKeyId)));
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).disable(otherKeyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(primaryKeyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getKeyId()).isEqualTo(otherKeyId);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.DISABLED);
  }

  @Test
  public void testDisable_keyIsPrimary_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(primaryKeyId), createEnabledKey(otherKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                KeysetManager.withKeysetHandle(handle)
                    .disable(primaryKeyId)
                    .getKeysetHandle()
                    .getKeyset());
    assertThat(e.toString()).contains("cannot disable the primary key");
  }

  @Test
  public void testDisable_keyDestroyed_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(primaryKeyId), createDestroyedKey(otherKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                KeysetManager.withKeysetHandle(handle)
                    .disable(otherKeyId)
                    .getKeysetHandle()
                    .getKeyset());
    assertThat(e.toString()).contains("cannot disable key");
  }

  @Test
  public void testDisable_keyNotFound_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(createDisabledKey(keyId)));

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).disable(keyId + 1));
    assertThat(e.toString()).contains("key not found");
  }

  @Test
  public void testDestroy_shouldDestroyKey() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(primaryKeyId), createEnabledKey(otherKeyId)));
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).destroy(otherKeyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(primaryKeyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getKeyId()).isEqualTo(otherKeyId);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.DESTROYED);
    assertThat(keyset.getKey(1).hasKeyData()).isFalse();
  }

  @Test
  public void testDestroy_keyIsPrimary_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(primaryKeyId), createEnabledKey(otherKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                KeysetManager.withKeysetHandle(handle)
                    .destroy(primaryKeyId)
                    .getKeysetHandle()
                    .getKeyset());
    assertThat(e.toString()).contains("cannot destroy the primary key");
  }

  @Test
  public void testDestroy_keyUnknownStatus_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId), createUnknownStatusKey(otherKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                KeysetManager.withKeysetHandle(handle)
                    .destroy(otherKeyId)
                    .getKeysetHandle()
                    .getKeyset());
    assertThat(e.toString()).contains("cannot destroy key");
  }

  @Test
  public void testDestroy_keyNotFound_shouldThrowException() throws Exception {
    int keyId = 42;
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(createDisabledKey(keyId)));

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).destroy(keyId + 1));
    assertThat(e.toString()).contains("key not found");
  }

  @Test
  public void testDelete_shouldDeleteKey() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(primaryKeyId), createEnabledKey(otherKeyId)));
    Keyset keyset =
        KeysetManager.withKeysetHandle(handle).delete(otherKeyId).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(primaryKeyId);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  @Test
  public void testDelete_keyIsPrimary_shouldThrowException() throws Exception {
    int primaryKeyId = 42;
    int otherKeyId = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(primaryKeyId), createEnabledKey(otherKeyId)));
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                KeysetManager.withKeysetHandle(handle)
                    .delete(primaryKeyId)
                    .getKeysetHandle()
                    .getKeyset());
    assertThat(e.toString()).contains("cannot delete the primary key");
  }

  @Test
  public void testDelete_keyNotFound_shouldThrowException() throws Exception {
    int keyId1 = 42;
    final int keyId2 = 43;
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(createEnabledKey(keyId1), createEnabledKey(keyId2)));

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> KeysetManager.withKeysetHandle(handle).delete(44));
    assertThat(e.toString()).contains("key not found");
  }

  @Test
  public void testRotate_shouldAddNewKeyAndSetPrimaryKeyId() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    @SuppressWarnings("deprecation") // Need to test the deprecated function
    Keyset keyset =
        KeysetManager.withEmptyKeyset().rotate(template.getProto()).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyset.getKey(0).getKeyId());
    TestUtil.assertHmacKey(template, keyset.getKey(0));
  }

  @Test
  public void testRotate_bogusKeyTemplate_shouldThrowException() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate bogus =
        TestUtil.createKeyTemplateWithNonExistingTypeUrl();

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> KeysetManager.withEmptyKeyset().rotate(bogus));
    TestUtil.assertExceptionContains(e, "No key manager found for key type");
  }

  @Test
  public void testRotate_existingKeyset_shouldAddNewKeyAndSetPrimaryKeyId() throws Exception {
    @SuppressWarnings("deprecation") // Need to test the deprecated function
    KeysetHandle existing =
        KeysetManager.withEmptyKeyset()
            .rotate(KeyTemplates.get("HMAC_SHA256_128BITTAG").getProto())
            .getKeysetHandle();
    @SuppressWarnings("deprecation") // Need to test the deprecated function
    Keyset keyset =
        KeysetManager.withKeysetHandle(existing)
            .rotate(KeyTemplates.get("HMAC_SHA256_256BITTAG").getProto())
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyset.getKey(1).getKeyId());
    TestUtil.assertHmacKey(KeyTemplates.get("HMAC_SHA256_128BITTAG"), keyset.getKey(0));
    TestUtil.assertHmacKey(KeyTemplates.get("HMAC_SHA256_256BITTAG"), keyset.getKey(1));
  }

  @Test
  public void testAdd_shouldAddNewKey() throws Exception {
    KeyTemplate kt = KeyTemplates.get("AES128_GCM");
    Keyset keyset = KeysetManager.withEmptyKeyset().add(kt).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    // No primary key because add doesn't automatically promote the new key to primary.
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(0);

    Keyset.Key key = keyset.getKey(0);
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(key.hasKeyData()).isTrue();
    assertThat(key.getKeyData().getTypeUrl()).isEqualTo(kt.getTypeUrl());

    AesGcmKeyFormat aesGcmKeyFormat =
        AesGcmKeyFormat.parseFrom(kt.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey.getKeyValue().size()).isEqualTo(aesGcmKeyFormat.getKeySize());
  }

  @Test
  public void testAdd_shouldAddNewKey_proto() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = KeyTemplates.get("HMAC_SHA256_128BITTAG");
    Keyset keyset = KeysetManager.withEmptyKeyset().add(template).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(0);
    TestUtil.assertHmacKey(template, keyset.getKey(0));
  }

  @Test
  public void testAdd_bogusKeyTemplate_shouldThrowException() throws Exception {
    KeyTemplate bogus =
        KeyTemplate.create("does not exist", new byte[0], KeyTemplate.OutputPrefixType.TINK);

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> KeysetManager.withEmptyKeyset().add(bogus));
    TestUtil.assertExceptionContains(e, "No key manager found for key type");
  }

  @Test
  public void testAdd_bogusKeyTemplate_shouldThrowException_proto() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate bogus =
        TestUtil.createKeyTemplateWithNonExistingTypeUrl();

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> KeysetManager.withEmptyKeyset().add(bogus));
    TestUtil.assertExceptionContains(e, "No key manager found for key type");
  }

  @Test
  public void testAdd_protoKeyTemplateWithoutPrefix_shouldThrowException() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate templateWithoutPrefix =
        MacKeyTemplates.createHmacKeyTemplate(32, 16, HashType.SHA256).toBuilder()
            .setOutputPrefixType(OutputPrefixType.UNKNOWN_PREFIX)
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetManager.withEmptyKeyset().add(templateWithoutPrefix));
  }

  @Test
  public void testAdd_existingKeySet_shouldAddNewKey() throws Exception {
    KeyTemplate kt1 = AesGcmKeyManager.aes128GcmTemplate();
    KeysetHandle existing = KeysetManager.withEmptyKeyset().add(kt1).getKeysetHandle();
    KeyTemplate kt2 = AesGcmKeyManager.aes256GcmTemplate();
    Keyset keyset = KeysetManager.withKeysetHandle(existing).add(kt2).getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    // None of the keys are primary.
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(0);

    Keyset.Key key1 = keyset.getKey(0);
    assertThat(key1.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key1.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(key1.hasKeyData()).isTrue();
    assertThat(key1.getKeyData().getTypeUrl()).isEqualTo(kt1.getTypeUrl());

    AesGcmKeyFormat aesGcmKeyFormat1 =
        AesGcmKeyFormat.parseFrom(kt1.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey1 =
        AesGcmKey.parseFrom(key1.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey1.getKeyValue().size()).isEqualTo(aesGcmKeyFormat1.getKeySize());

    Keyset.Key key2 = keyset.getKey(1);
    assertThat(key2.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key2.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(key2.hasKeyData()).isTrue();
    assertThat(key2.getKeyData().getTypeUrl()).isEqualTo(kt2.getTypeUrl());

    AesGcmKeyFormat aesGcmKeyFormat2 =
        AesGcmKeyFormat.parseFrom(kt2.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey2 =
        AesGcmKey.parseFrom(key2.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey2.getKeyValue().size()).isEqualTo(aesGcmKeyFormat2.getKeySize());
  }

  @Test
  public void testAdd_existingKeySet_shouldAddNewKey_proto() throws Exception {
    KeysetHandle existing =
        KeysetManager.withEmptyKeyset()
            .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
            .getKeysetHandle();
    int existingPrimaryKeyId = existing.getKeyset().getPrimaryKeyId();
    Keyset keyset =
        KeysetManager.withKeysetHandle(existing)
            .add(MacKeyTemplates.HMAC_SHA256_256BITTAG)
            .getKeysetHandle()
            .getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(existingPrimaryKeyId);
    TestUtil.assertHmacKey(KeyTemplates.get("HMAC_SHA256_128BITTAG"), keyset.getKey(0));
    TestUtil.assertHmacKey(KeyTemplates.get("HMAC_SHA256_256BITTAG"), keyset.getKey(1));
  }

  @Test
  public void addKeyHandle_newKeyset_shouldAddKey() throws Exception {
    KeyTemplate keyTemplate = KeyTemplates.get("AES256_GCM");
    KeyHandle keyHandle = KeyHandle.generateNew(keyTemplate);
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();

    keysetManager = keysetManager.add(keyHandle);

    KeysetHandle keysetHandle = keysetManager.getKeysetHandle();
    Keyset keyset = keysetHandle.getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(1);
    Keyset.Key key = keyset.getKey(0);
    expect.that(key.getKeyId()).isEqualTo(keyHandle.getId());
    expect.that(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    expect.that(key.hasKeyData()).isTrue();
    expect.that(key.getKeyData().getTypeUrl()).isEqualTo(keyTemplate.getTypeUrl());
    AesGcmKeyFormat aesGcmKeyFormat =
        AesGcmKeyFormat.parseFrom(keyTemplate.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesGcmKey.getKeyValue().size()).isEqualTo(aesGcmKeyFormat.getKeySize());
    // No primary key because add doesn't automatically promote the new key to primary.
    assertThrows(GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void addKeyHandle_existingKeyset_shouldAddKey() throws Exception {
    KeyTemplate keyTemplate1 = KeyTemplates.get("AES128_GCM_RAW");
    KeyHandle keyHandle1 = KeyHandle.generateNew(keyTemplate1);
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset().add(keyHandle1);
    keysetManager.setPrimary(keyHandle1.getId());
    KeyTemplate keyTemplate2 = KeyTemplates.get("AES256_GCM_RAW");
    KeyHandle keyHandle2 = KeyHandle.generateNew(keyTemplate2);

    keysetManager = keysetManager.add(keyHandle2);

    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(2);
    expect.that(keyset.getPrimaryKeyId()).isEqualTo(keyHandle1.getId());
    Keyset.Key key1 = keyset.getKey(0);
    expect.that(key1.getKeyId()).isEqualTo(keyHandle1.getId());
    expect.that(key1.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key1.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    expect.that(key1.hasKeyData()).isTrue();
    expect.that(key1.getKeyData().getTypeUrl()).isEqualTo(keyTemplate1.getTypeUrl());
    AesGcmKeyFormat aesGcmKeyFormat1 =
        AesGcmKeyFormat.parseFrom(
            keyTemplate1.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey1 =
        AesGcmKey.parseFrom(key1.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesGcmKey1.getKeyValue().size()).isEqualTo(aesGcmKeyFormat1.getKeySize());
    Keyset.Key key2 = keyset.getKey(1);
    expect.that(key2.getKeyId()).isEqualTo(keyHandle2.getId());
    expect.that(key2.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key2.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    expect.that(key2.hasKeyData()).isTrue();
    expect.that(key2.getKeyData().getTypeUrl()).isEqualTo(keyTemplate2.getTypeUrl());
    AesGcmKeyFormat aesGcmKeyFormat2 =
        AesGcmKeyFormat.parseFrom(
            keyTemplate2.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey2 =
        AesGcmKey.parseFrom(key2.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesGcmKey2.getKeyValue().size()).isEqualTo(aesGcmKeyFormat2.getKeySize());
  }

  @Test
  public void addKeyHandle_fromKeysetWithDisabledKey_shouldCopyStatusCorrectly() throws Exception {
    KeyTemplate keyTemplate = KeyTemplates.get("AES128_GCM_RAW");
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    for (int i = 0; i < 3; i++) {
      keysetManager.add(keyTemplate);
    }
    keysetManager.disable(keysetManager.getKeysetHandle().getKeys().get(0).getId());
    KeysetHandle keysetHandle = keysetManager.getKeysetHandle();
    List<KeyHandle> keyList = keysetHandle.getKeys();
    KeysetManager copiedKeysetManager = KeysetManager.withEmptyKeyset();

    for (KeyHandle key : keyList) {
      copiedKeysetManager.add(key);
    }

    KeysetHandle copiedKeysetHandle = copiedKeysetManager.getKeysetHandle();
    List<KeyHandle> copiedKeyList = copiedKeysetHandle.getKeys();
    expect.that(copiedKeyList.size()).isEqualTo(keyList.size());
    for (int i = 0; i < copiedKeyList.size(); i++) {
      KeyHandle copiedKeyHandle = copiedKeyList.get(i);
      KeyHandle keyHandle = keyList.get(i);
      expect.that(copiedKeyHandle.getStatus()).isEqualTo(keyHandle.getStatus());
      expect.that(copiedKeyHandle.hasSecret()).isEqualTo(keyHandle.hasSecret());
      expect.that(copiedKeyHandle.getId()).isEqualTo(keyHandle.getId());
      ProtoKey copiedProtoKey =
          (ProtoKey) copiedKeyHandle.getKey(SecretKeyAccess.insecureSecretAccess());
      ProtoKey protoKey = (ProtoKey) keyHandle.getKey(SecretKeyAccess.insecureSecretAccess());
      expect.that(copiedProtoKey.getOutputPrefixType()).isEqualTo(protoKey.getOutputPrefixType());
      expect.that(copiedProtoKey.getProtoKey()).isEqualTo(protoKey.getProtoKey());
    }
  }

  @Test
  public void addKeyHandle_existingKeyset_collidingKeyIds_shouldThrow() throws Exception {
    KeyTemplate keyTemplate1 = KeyTemplates.get("AES128_GCM_RAW");
    KeyHandle keyHandle1 = KeyHandle.generateNew(keyTemplate1);
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset().add(keyHandle1);

    assertThrows(GeneralSecurityException.class, () -> keysetManager.add(keyHandle1));
  }

  @Test
  public void addKeyHandle_unsupportedTinkKey_shouldThrow() throws Exception {
    TinkKey tinkKey =
        new TinkKey() {
          @Override
          public boolean hasSecret() {
            return false;
          }

          @Override
          public KeyTemplate getKeyTemplate() {
            throw new UnsupportedOperationException();
          }
        };
    KeyHandle keyHandle = KeyHandle.createFromKey(tinkKey, KeyAccess.publicAccess());
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();

    assertThrows(UnsupportedOperationException.class, () -> keysetManager.add(keyHandle));
  }

  @Test
  public void addKeyHandleWithKeyAccess_newKeyset_shouldAddKey() throws Exception {
    KeyTemplate keyTemplate = KeyTemplates.get("AES128_GCM");
    KeyHandle keyHandle = KeyHandle.generateNew(keyTemplate);
    KeyAccess keyAccess = SecretKeyAccess.insecureSecretAccess();
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();

    keysetManager = keysetManager.add(keyHandle, keyAccess);

    KeysetHandle keysetHandle = keysetManager.getKeysetHandle();
    Keyset keyset = keysetHandle.getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(1);
    Keyset.Key key = keyset.getKey(0);
    expect.that(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    expect.that(key.hasKeyData()).isTrue();
    expect.that(key.getKeyData().getTypeUrl()).isEqualTo(keyTemplate.getTypeUrl());
    AesGcmKeyFormat aesGcmKeyFormat =
        AesGcmKeyFormat.parseFrom(keyTemplate.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesGcmKey.getKeyValue().size()).isEqualTo(aesGcmKeyFormat.getKeySize());
    // No primary key because add doesn't automatically promote the new key to primary.
    assertThrows(GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void addKeyHandleWithKeyAccess_existingKeyset_shouldAddKey() throws Exception {
    KeyTemplate keyTemplate1 = KeyTemplates.get("AES128_GCM");
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset().add(keyTemplate1);
    KeyTemplate keyTemplate2 = KeyTemplates.get("AES256_GCM");
    KeyAccess keyAccess = SecretKeyAccess.insecureSecretAccess();
    KeyHandle keyHandle =
        KeyHandle.createFromKey(
            new ProtoKey(Registry.newKeyData(keyTemplate2), keyTemplate2.getOutputPrefixType()),
            keyAccess);

    keysetManager = keysetManager.add(keyHandle, keyAccess);

    KeysetHandle keysetHandle = keysetManager.getKeysetHandle();
    Keyset keyset = keysetHandle.getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(2);
    Keyset.Key key1 = keyset.getKey(0);
    expect.that(key1.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key1.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    expect.that(key1.hasKeyData()).isTrue();
    expect.that(key1.getKeyData().getTypeUrl()).isEqualTo(keyTemplate1.getTypeUrl());
    AesGcmKeyFormat aesGcmKeyFormat1 =
        AesGcmKeyFormat.parseFrom(
            keyTemplate1.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey1 =
        AesGcmKey.parseFrom(key1.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesGcmKey1.getKeyValue().size()).isEqualTo(aesGcmKeyFormat1.getKeySize());
    Keyset.Key key2 = keyset.getKey(1);
    expect.that(key2.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key2.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    expect.that(key2.hasKeyData()).isTrue();
    expect.that(key2.getKeyData().getTypeUrl()).isEqualTo(keyTemplate2.getTypeUrl());
    AesGcmKeyFormat aesGcmKeyFormat2 =
        AesGcmKeyFormat.parseFrom(
            keyTemplate2.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey2 =
        AesGcmKey.parseFrom(key2.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesGcmKey2.getKeyValue().size()).isEqualTo(aesGcmKeyFormat2.getKeySize());
    // No primary key because add doesn't automatically promote the new key to primary.
    assertThrows(GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void addKeyHandleWithKeyAccess_unsupportedTinkKey_shouldThrow() throws Exception {
    TinkKey tinkKey =
        new TinkKey() {
          @Override
          public boolean hasSecret() {
            return false;
          }

          @Override
          public KeyTemplate getKeyTemplate() {
            throw new UnsupportedOperationException();
          }
        };
    KeyAccess keyAccess = KeyAccess.publicAccess();
    KeyHandle keyHandle = KeyHandle.createFromKey(tinkKey, keyAccess);
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();

    assertThrows(
        UnsupportedOperationException.class, () -> keysetManager.add(keyHandle, keyAccess));
  }

  @Test
  public void testAddNewKey_onePrimary() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    int keyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(keyId);
    TestUtil.assertHmacKey(KeyTemplates.get("HMAC_SHA256_128BITTAG"), keyset.getKey(0));
  }

  @Test
  public void testAddNewKey_onePrimaryAnotherPrimary() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    int primaryKeyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(primaryKeyId);
  }

  @Test
  public void testAddNewKey_primaryThenNonPrimary() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    int primaryKeyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, false);
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(2);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(primaryKeyId);
  }

  @Test
  public void testAddNewKey_addThenDestroy() throws Exception {
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, true);
    int secondaryKeyId = keysetManager.addNewKey(MacKeyTemplates.HMAC_SHA256_128BITTAG, false);
    keysetManager.destroy(secondaryKeyId);
    Keyset keyset = keysetManager.getKeysetHandle().getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(2);
    // One of the two keys is destroyed and doesn't have keyData anymore.
    assertTrue(!keyset.getKey(0).hasKeyData() || !keyset.getKey(1).hasKeyData());
  }

  private void manipulateKeyset(KeysetManager manager) {
    try {
      com.google.crypto.tink.proto.KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
      manager.rotate(template).add(template).rotate(template).add(template);
    } catch (GeneralSecurityException e) {
      fail("should not throw exception: " + e);
    }
  }

  @Test
  public void testThreadSafety_manipulateKeyset_shouldWork() throws Exception {
    final KeysetManager manager = KeysetManager.withEmptyKeyset();
    Thread thread1 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                manipulateKeyset(manager);
              }
            });
    Thread thread2 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                manipulateKeyset(manager);
              }
            });
    Thread thread3 =
        new Thread(
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
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(12);
  }

  private void enableSetPrimaryKey(KeysetManager manager, int keyId) {
    try {
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
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId),
                createEnabledKey(keyId2),
                createDisabledKey(keyId3)));
    final KeysetManager manager = KeysetManager.withKeysetHandle(handle);

    Thread thread1 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                enableSetPrimaryKey(manager, primaryKeyId);
              }
            });
    Thread thread2 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                enableSetPrimaryKey(manager, keyId2);
              }
            });
    Thread thread3 =
        new Thread(
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
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(3);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(2).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  private void disableEnableSetPrimaryKey(KeysetManager manager, int keyId) {
    try {
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
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId),
                createEnabledKey(keyId2),
                createDisabledKey(keyId3)));
    final KeysetManager manager = KeysetManager.withKeysetHandle(handle);

    Thread thread2 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                disableEnableSetPrimaryKey(manager, keyId2);
              }
            });
    Thread thread3 =
        new Thread(
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
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(3);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(1).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(2).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }

  private void enableDisableDeleteKey(KeysetManager manager, int keyId) {
    try {
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
    KeysetHandle handle =
        KeysetHandle.fromKeyset(
            TestUtil.createKeyset(
                createEnabledKey(primaryKeyId),
                createEnabledKey(keyId2),
                createDisabledKey(keyId3)));
    final KeysetManager manager = KeysetManager.withKeysetHandle(handle);

    Thread thread2 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                enableDisableDeleteKey(manager, keyId2);
              }
            });
    Thread thread3 =
        new Thread(
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
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(keyset.getPrimaryKeyId());
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
  }
}
