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
import com.google.crypto.tink.proto.Keyset;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Static methods for reading cleartext keysets that don't contain any secret key material.
 *
 * @since 1.0.0
 * @deprecated use {@link KeysetHandle#readNoSecret} instead
 */
@Deprecated
public final class NoSecretKeysetHandle {
  /**
   * @return a new keyset handle from {@code serialized} which is a serialized {@link Keyset}.
   * @throws GeneralSecurityException
   * @deprecated use {@link NoSecretKeysetHandle#read} instead
   */
  @Deprecated
  public static final KeysetHandle parseFrom(final byte[] serialized)
      throws GeneralSecurityException {
    try {
      Keyset keyset = Keyset.parseFrom(serialized, ExtensionRegistryLite.getEmptyRegistry());
      validate(keyset);
      return KeysetHandle.fromKeyset(keyset);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @return a new keyset handle from a keyset obtained from {@code reader}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle read(KeysetReader reader)
      throws GeneralSecurityException, IOException {
    Keyset keyset = reader.read();
    validate(keyset);
    return KeysetHandle.fromKeyset(keyset);
  }

  /**
   * Validates that {@code keyset} doesn't contain any secret key material.
   *
   * @throws GeneralSecurityException if {@code keyset} contains secret key material.
   */
  private static void validate(Keyset keyset) throws GeneralSecurityException {
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL
          || key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.SYMMETRIC
          || key.getKeyData().getKeyMaterialType() == KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE) {
        throw new GeneralSecurityException("keyset contains secret key material");
      }
    }
  }

  private NoSecretKeysetHandle() {}
}
