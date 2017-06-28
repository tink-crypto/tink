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

import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Creates keyset handles from keysets that are encrypted with a {@code MasterKey}
 */
public final class EncryptedKeysetHandle {
  /**
   * @return a new {@code KeysetHandle} from {@code serialized} which is a serialized
   * {@code EncryptedKeyset}. The keyset is encrypted with {@code masterKey}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle parseFrom(final byte[] serialized, Aead masterKey)
      throws GeneralSecurityException {
    try {
      EncryptedKeyset keyset = EncryptedKeyset.parseFrom(serialized);
      EncryptedKeysetHandle.assertEnoughKeyMaterial(keyset);
      return parseFrom(keyset, masterKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @return a new {@code KeysetHandle} from {@code inputStream} which reads a serialized
   * {@code EncryptedKeyset}. The keyset is encrypted with {@code masterKey}.
   * @throws GeneralSecurityException, IOException
   */
  public static final KeysetHandle parseFrom(final InputStream inputStream, Aead masterKey)
      throws GeneralSecurityException, IOException {
    try {
      EncryptedKeyset keyset = EncryptedKeyset.parseFrom(inputStream);
      EncryptedKeysetHandle.assertEnoughKeyMaterial(keyset);
      return parseFrom(keyset, masterKey);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @return a new {@code KeysetHandle} from {@code encryptedKeysetProto}. The keyset is
   * encrypted with {@code masterKey}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle parseFrom(EncryptedKeyset proto, Aead masterKey)
      throws GeneralSecurityException {
    EncryptedKeysetHandle.assertEnoughKeyMaterial(proto);
    try {
      final Keyset keyset = Keyset.parseFrom(masterKey.decrypt(
          proto.getEncryptedKeyset().toByteArray(), /* additionalData= */new byte[0]));
      // check emptiness here too, in case the encrypted keys unwrapped to nothing?
      KeysetHandle.assertEnoughKeyMaterial(keyset);
      return new KeysetHandle(keyset, proto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset, corrupted key material");
    }
  }

  /**
   * @return a new keyset handle that contains a single fresh key generated
   * according to the {@code keyTemplate}. The keyset is encrypted with {@code masterKey}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle generateNew(KeyTemplate keyTemplate, Aead masterKey)
      throws GeneralSecurityException {
    return new KeysetManager.Builder()
        .setKeyTemplate(keyTemplate)
        .setMasterKey(masterKey)
        .build()
        .rotate()
        .getKeysetHandle();
  }

  /**
   * Validates that an encrypted keyset contains enough key material to build a keyset on,
   * and throws otherwise.
   * @throws GeneralSecurityException
   */
  public static void assertEnoughKeyMaterial(EncryptedKeyset keyset)
      throws GeneralSecurityException {
    if (keyset == null || keyset.getEncryptedKeyset().size() == 0) {
      throw new GeneralSecurityException("empty keyset");
    }
  }
}
