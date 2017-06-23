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

import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Creates keyset handles from cleartext keysets. This API allows loading cleartext keysets, thus
 * its usage should be restricted. Users that need to load keysets that don't contain any secret
 * key material can use {@code NoSecretKeysetHandle}.
 */
public final class CleartextKeysetHandle {
  /**
   * @return a new keyset handle from {@code serialized} which is a serialized {@code Keyset}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle parseFrom(final byte[] serialized)
      throws GeneralSecurityException {
    try {
      Keyset keyset = Keyset.parseFrom(serialized);
      KeysetHandle.assertEnoughKeyMaterial(keyset);
      return parseFrom(keyset);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @return a new keyset handle from {@code inputStream}, which reads a serialized {@code Keyset}.
   * @throws GeneralSecurityException, IOException
   */
  public static final KeysetHandle parseFrom(final InputStream inputStream)
      throws GeneralSecurityException, IOException {
    try {
      Keyset keyset = Keyset.parseFrom(inputStream);
      KeysetHandle.assertEnoughKeyMaterial(keyset);
      return parseFrom(keyset);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @return a new keyset handle from {@code encryptedKeySet}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle parseFrom(Keyset keyset)
      throws GeneralSecurityException {
    KeysetHandle.assertEnoughKeyMaterial(keyset);
    return new KeysetHandle(keyset);
  }

  /**
   * @return a new keyset handle that contains a single fresh key generated
   * according to the {@code keyTemplate}.
   * @throws GeneralSecurityException
   */
  public static final KeysetHandle generateNew(KeyTemplate keyTemplate)
      throws GeneralSecurityException {
    return new KeysetManager.Builder()
        .setKeyTemplate(keyTemplate)
        .build()
        .rotate()
        .getKeysetHandle();
  }
}
