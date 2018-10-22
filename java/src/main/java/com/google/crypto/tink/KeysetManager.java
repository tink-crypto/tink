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
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
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
  @GuardedBy("this")
  public synchronized KeysetHandle getKeysetHandle() throws GeneralSecurityException {
    return KeysetHandle.fromKeyset(keysetBuilder.build());
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}, and sets the new key as the
   * primary key.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   */
  @GuardedBy("this")
  public synchronized KeysetManager rotate(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    addNewKey(keyTemplate, true);
    return this;
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *     keyTemplate}
   */
  @GuardedBy("this")
  public synchronized KeysetManager add(KeyTemplate keyTemplate) throws GeneralSecurityException {
    addNewKey(keyTemplate, false);
    return this;
  }

  /**
   * Generates a fresh key using {@code keyTemplate} and returns the {@code keyId} of it. In case
   * {@isPrimary} is true the generated key will be the new primary.
   */
  @GuardedBy("this")
  public synchronized int addNewKey(KeyTemplate keyTemplate, boolean asPrimary)
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
  @GuardedBy("this")
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
  @GuardedBy("this")
  @Deprecated
  public synchronized KeysetManager promote(int keyId) throws GeneralSecurityException {
    return setPrimary(keyId);
  }

  /**
   * Enables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found
   */
  @GuardedBy("this")
  public synchronized KeysetManager enable(int keyId) throws GeneralSecurityException {
    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED
            && key.getStatus() != KeyStatusType.DISABLED) {
          throw new GeneralSecurityException(
              "cannot enable key with id " + keyId + " and status " + key.getStatus());
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
  @GuardedBy("this")
  public synchronized KeysetManager disable(int keyId) throws GeneralSecurityException {
    if (keyId == keysetBuilder.getPrimaryKeyId()) {
      throw new GeneralSecurityException("cannot disable the primary key");
    }

    for (int i = 0; i < keysetBuilder.getKeyCount(); i++) {
      Keyset.Key key = keysetBuilder.getKey(i);
      if (key.getKeyId() == keyId) {
        if (key.getStatus() != KeyStatusType.ENABLED
            && key.getStatus() != KeyStatusType.DISABLED) {
          throw new GeneralSecurityException(
              "cannot disable key with id " + keyId + " and status " + key.getStatus());
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
  @GuardedBy("this")
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
  @GuardedBy("this")
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
          throw new GeneralSecurityException(
              "cannot destroy key with id " + keyId + " and status " + key.getStatus());
        }
        keysetBuilder.setKey(
            i, key.toBuilder().setStatus(KeyStatusType.DESTROYED).clearKeyData().build());
        return this;
      }
    }
    throw new GeneralSecurityException("key not found: " + keyId);
  }

  @GuardedBy("this")
  private synchronized Keyset.Key newKey(KeyTemplate keyTemplate) throws GeneralSecurityException {
    KeyData keyData = Registry.newKeyData(keyTemplate);
    int keyId = newKeyId();
    OutputPrefixType outputPrefixType = keyTemplate.getOutputPrefixType();
    if (outputPrefixType == OutputPrefixType.UNKNOWN_PREFIX) {
      outputPrefixType = OutputPrefixType.TINK;
    }
    return Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setKeyId(keyId)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(outputPrefixType)
        .build();
  }

  @GuardedBy("this")
  private synchronized int newKeyId() {
    int keyId = randPositiveInt();
    while (true) {
      for (Keyset.Key key : keysetBuilder.getKeyList()) {
        if (key.getKeyId() == keyId) {
          keyId = randPositiveInt();
          continue;
        }
      }
      break;
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
      result =
          ((rand[0] & 0x7f) << 24)
              | ((rand[1] & 0xff) << 16)
              | ((rand[2] & 0xff) << 8)
              | (rand[3] & 0xff);
    }
    return result;
  }
}
