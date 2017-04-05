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

import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KmsEncryptedKeyset;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Creates keyset handles from keysets that are encrypted with a key in some KMS.
 */
public final class KmsEncryptedKeysetHandle {
  /**
   * @return a new keyset handle from {@code serialized} which is a serialized
   * {@code KmsEncryptedKeyset}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle parseFrom(final byte[] serialized)
      throws GeneralSecurityException {
    try {
      KmsEncryptedKeyset keyset = KmsEncryptedKeyset.parseFrom(serialized);
      return parseFrom(keyset);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @return a new keyset handle from {@code encryptedKeyset}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle parseFrom(KmsEncryptedKeyset kmsEncryptedKeyset)
      throws GeneralSecurityException {
    byte[] encryptedKeyset = kmsEncryptedKeyset.getEncryptedKeyset().toByteArray();
    if (encryptedKeyset.length == 0 || !kmsEncryptedKeyset.hasKmsKey()) {
      throw new GeneralSecurityException("invalid keyset, needs encrypted key material");
    }
    Aead aead = Registry.INSTANCE.getPrimitive(kmsEncryptedKeyset.getKmsKey());
    try {
      final Keyset keyset = Keyset.parseFrom(aead.decrypt(encryptedKeyset, new byte[0] /* aad */));
      return new KeysetHandle(keyset, encryptedKeyset);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset, corrupted key material");
    }
  }
}
