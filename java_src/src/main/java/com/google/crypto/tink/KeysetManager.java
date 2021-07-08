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

import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.annotation.concurrent.GuardedBy;

/**
 * Manages a {@link Keyset} proto, with convenience methods that rotate, disable, enable or destroy
 * keys.
 *
 * @since 1.0.0
 */
public final class KeysetManager {
  @GuardedBy("this")
  private final Keyset.Builder keysetBuilder;

  private KeysetManager(Keyset.Builder val) {
    keysetBuilder = val;
  }

  /** @return a {@link KeysetManager} for the keyset manged by {@code val} */
  public static KeysetManager withKeysetHandle(KeysetHandle val) {
    return new KeysetManager(val.getKeyset().toBuilder());
  }

  /** @return a {@link KeysetManager} for an empty keyset. */
  public static KeysetManager withEmptyKeyset() {
    return new KeysetManager(Keyset.newBuilder());
  }

  /** @return a {@link KeysetHandle} of the managed keyset */
  public synchronized KeysetHandle getKeysetHandle() throws GeneralSecurityException {
    return KeysetHandle.fromKeyset(keysetBuilder.build());
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}, and sets the new key as the
   * primary key.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   * @deprecated Please use {@link #add}. This method adds a new key and immediately promotes it to
   *     primary. However, when you do keyset rotation, you almost never want to make the new key
   *     primary, because old binaries don't know the new key yet.
   */
  @Deprecated
  public synchronized KeysetManager rotate(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    addNewKey(keyTemplate, true);
    return this;
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   * @deprecated This method takes a KeyTemplate proto, which is an internal implementation detail.
   *     Please use the add method that takes a {@link KeyTemplate} POJO.
   */
  @Deprecated
  public synchronized KeysetManager add(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    addNewKey(keyTemplate, false);
    return this;
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   */
  public synchronized KeysetManager add(KeyTemplate keyTemplate) throws GeneralSecurityException {
    addNewKey(keyTemplate.getProto(), false);
    return this;
  }

  /**
   * Adds the input {@code KeyHandle} to the existing keyset with {@code OutputPrefixType.TINK}.
   *
   * @throws GeneralSecurityException if the given {@code KeyAccess} does not grant access to the
   *     key contained in the {@code KeyHandle}.
   * @throws UnsupportedOperationException if the {@code KeyHandle} contains a {@code TinkKey} which
   *     is not a {@code ProtoKey}.
   */
  public synchronized KeysetManager add(KeyHandle keyHandle, KeyAccess access)
      throws GeneralSecurityException {
    ProtoKey pkey;
    try {
      pkey = (ProtoKey) keyHandle.getKey(access);
    } catch (ClassCastException e) {
      throw new UnsupportedOperationException(
          "KeyHandles which contain TinkKeys that are not ProtoKeys are not yet supported.", e);
    }
    keysetBuilder.addKey(
        createKeysetKey(pkey.getProtoKey(), KeyTemplate.toProto(pkey.getOutputPrefixType())));
    return this;
  }

  /**
   * Generates a fresh key using {@code keyTemplate} and returns the {@code keyId} of it. In case
   * {@code asPrimary} is true the generated key will be the new primary.
   *
   * @deprecated Please use {@link #add}. This method adds a new key and when {@code asPrimary} is
   *     true immediately promotes it to primary. However, when you do keyset rotation, you almost
   *     never want to make the new key primary, because old binaries don't know the new key yet.
   */
  @Deprecated
  public synchronized int addNewKey(
      com.google.crypto.tink.proto.KeyTemplate keyTemplate, boolean asPrimary)
      throws GeneralSecurityException {
    Keyset.Key key = newKey(keyTemplate);
    keysetBuilder.addKey(key);
    if (asPrimary) {
      keysetBuilder.setPrimaryKeyId(key.getKeyId());
    }
    return key.getKeyId();
  }

  /**
   * Sets the key with {@code keyId} as primary.
   *
   * @throws GeneralSecurityException if the key is not found or not enabled
   */
  public synchronized KeysetManager setPrimary(int keyId) throws GeneralSecurityException {
    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (!key.getStatus().equals(KeyStatusType.ENABLED)) {
          throw new GeneralSecurityException(
              "cannot set key as primary because it's not enabled: " + keyId);
        }
        keysetBuilder.setPrimaryKeyId(keyId);
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Sets the key with {@code keyId} as primary.
   *
   * @throws GeneralSecurityException if the key is not found or not enabled
   * @deprecated use {@link setPrimary}
   */
  @Deprecated
  public synchronized KeysetManager promote(int keyId) throws GeneralSecurityException {
    return setPrimary(keyId);
  }

  /**
   * Enables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found
   */
  public synchronized KeysetManager enable(int keyId) throws GeneralSecurityException {
    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED && key.getStatus() != KeyStatusType.DISABLED) {
          throw new GeneralSecurityException("cannot enable key with id " + keyId);
        }
        keysetBuilder.setKey(i, key.toBuilder().setStatus(KeyStatusType.ENABLED).build());
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Disables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  public synchronized KeysetManager disable(int keyId) throws GeneralSecurityException {
    if (keyId == keysetBuilder.getPrimaryKeyId()) {
      throw new GeneralSecurityException("cannot disable the primary key");
    }

    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED && key.getStatus() != KeyStatusType.DISABLED) {
          throw new GeneralSecurityException("cannot disable key with id " + keyId);
        }
        keysetBuilder.setKey(i, key.toBuilder().setStatus(KeyStatusType.DISABLED).build());
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Deletes the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  public synchronized KeysetManager delete(int keyId) throws GeneralSecurityException {
    if (keyId == keysetBuilder.getPrimaryKeyId()) {
      throw new GeneralSecurityException("cannot delete the primary key");
    }

    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        keysetBuilder.removeKey(i);
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  /**
   * Destroys the key material associated with the {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  public synchronized KeysetManager destroy(int keyId) throws GeneralSecurityException {
    if (keyId == keysetBuilder.getPrimaryKeyId()) {
      throw new GeneralSecurityException("cannot destroy the primary key");
    }

    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED
            && key.getStatus() != KeyStatusType.DISABLED
            && key.getStatus() != KeyStatusType.DESTROYED) {
          throw new GeneralSecurityException("cannot destroy key with id " + keyId);
        }
        keysetBuilder.setKey(
            i, key.toBuilder().setStatus(KeyStatusType.DESTROYED).clearKeyData().build());
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  private synchronized Keyset.Key newKey(com.google.crypto.tink.proto.KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    return createKeysetKey(Registry.newKeyData(keyTemplate), keyTemplate.getOutputPrefixType());
  }

  private synchronized Keyset.Key createKeysetKey(
      KeyData keyData, OutputPrefixType outputPrefixType) throws GeneralSecurityException {
    int keyId = newKeyId();
    if (outputPrefixType == OutputPrefixType.UNKNOWN_PREFIX) {
      throw new GeneralSecurityException("unknown output prefix type");
    }
    return Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setKeyId(keyId)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(outputPrefixType)
        .build();
  }

  private synchronized boolean keyIdExists(int keyId) {
    for (Keyset.Key key : keysetBuilder.getKeyList()) {
      if (key.getKeyId() == keyId) {
        return true;
      }
    }
    return false;
  }

  private synchronized int newKeyId() {
    int keyId = randPositiveInt();
    while (keyIdExists(keyId)) {
      keyId = randPositiveInt();
    }
    return keyId;
  }

  /** @return positive random int */
  private static int randPositiveInt() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] rand = new byte[4];
    int result = 0;
    while (result == 0) {
      secureRandom.nextBytes(rand);
      // TODO(b/148124847): Other languages create key_ids with the MSB set, so we should here too.
      result =
          ((rand[0] & 0x7f) << 24)
              | ((rand[1] & 0xff) << 16)
              | ((rand[2] & 0xff) << 8)
              | (rand[3] & 0xff);
    }
    return result;
  }
}
