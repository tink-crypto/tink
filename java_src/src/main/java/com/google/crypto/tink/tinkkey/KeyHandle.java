// Copyright 2020 Google LLC
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
package com.google.crypto.tink.tinkkey;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplate.OutputPrefixType;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Wraps a {@link TinkKey} and enforces access to the underlying {@link TinkKey} with {@link
 * KeyAccess}. Specifically, if the underlying {@link TinkKey} has a secret, then one can only get
 * it with a {@link SecretKeyAccess} instance.
 */
@Immutable
public final class KeyHandle {

  /**
   * KeyStatusType is metadata associated to a key which is only meaningful when the key is part of
   * a {@link Keyset}. A key's status in the Keyset is either ENABLED (able to perform cryptographic
   * operations), DISABLED (unable to perform operations, but could be re-enabled), or DESTROYED
   * (the key's data is no longer present in the keyset).
   */
  public enum KeyStatusType {
    ENABLED,
    DISABLED,
    DESTROYED;
  }

  /**
   * Returns a {@link KeyHandle} instance with {@code key} as the underlying {@link TinkKey} if the
   * caller provides the correct {@link KeyAccess} instance.
   *
   * @throws GeneralSecurityException if {@code access} does not grant access to {@code key}
   */
  public static KeyHandle createFromKey(TinkKey key, KeyAccess access)
      throws GeneralSecurityException {
    KeyHandle result = new KeyHandle(key);
    result.checkAccess(access);
    return result;
  }

  /**
   * Returns a {@link KeyHandle} instance where the underlying {@link TinkKey} wraps the input
   * {@code keyData}. The returned KeyHandle has a secret if keyData has key material of type
   * UNKNOWN_KEYMATERIAL, SYMMETRIC, or ASYMMETRIC_PRIVATE.
   *
   * @deprecated Use the KeyHandle(TinkKey, KeyAccess) constructor instead.
   */
  @Deprecated
  public static KeyHandle createFromKey(KeyData keyData, OutputPrefixType opt) {
    return new KeyHandle(new ProtoKey(keyData, opt));
  }

  private final TinkKey key;
  private final KeyStatusType status;
  private final int id;

  /**
   * Constructs a KeyHandle wrapping the input TinkKey. The KeyStatusType is set to ENABLED and an
   * arbitrary key ID is assigned.
   */
  private KeyHandle(TinkKey key) {
    this.key = key;
    this.status = KeyStatusType.ENABLED;
    this.id = Util.randKeyId();
  }

  /** Returns {@code true} if the underlying {@link TinkKey} has a secret. */
  public boolean hasSecret() {
    return key.hasSecret();
  }

  /** Returns the status of the key. See {@link KeyStatusType}. */
  public KeyStatusType getStatus() {
    return this.status;
  }

  /**
   * Returns the key ID of this key. The key ID is not guaranteed to be unique among all KeyHandles.
   */
  public int getId() {
    return id;
  }

  /**
   * Returns the underlying {@link TinkKey} key if {@code access} is a {@link SecretKeyAccess} and
   * the key has a secret, or if the key does not have a secret, otherwise throws a {@link
   * GeneralSecurityException}.
   */
  public TinkKey getKey(KeyAccess access) throws GeneralSecurityException {
    checkAccess(access);
    return key;
  }

  /**
   * Returns the {@link KeyTemplate} of the underlying {@link TinkKey}.
   *
   * @throws UnsupportedOperationException if the underlying {@link TinkKey} has not implemented
   *     getKeyTemplate().
   */
  public KeyTemplate getKeyTemplate() {
    return key.getKeyTemplate();
  }

  private void checkAccess(KeyAccess access) throws GeneralSecurityException {
    if (hasSecret() && !access.canAccessSecret()) {
      throw new GeneralSecurityException("No access");
    }
  }
}
