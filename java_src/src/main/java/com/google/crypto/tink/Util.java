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
// //////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink;

import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

/** Various helpers. */
final class Util {
  public static final Charset UTF_8 = Charset.forName("UTF-8");

  /** @return a KeysetInfo-proto from a {@code keyset} protobuf. */
  public static KeysetInfo getKeysetInfo(Keyset keyset) {
    KeysetInfo.Builder info = KeysetInfo.newBuilder().setPrimaryKeyId(keyset.getPrimaryKeyId());
    for (Keyset.Key key : keyset.getKeyList()) {
      info.addKeyInfo(getKeyInfo(key));
    }
    return info.build();
  }

  /** @return a KeyInfo-proto from a {@code key} protobuf. */
  public static KeysetInfo.KeyInfo getKeyInfo(Keyset.Key key) {
    return KeysetInfo.KeyInfo.newBuilder()
        .setTypeUrl(key.getKeyData().getTypeUrl())
        .setStatus(key.getStatus())
        .setOutputPrefixType(key.getOutputPrefixType())
        .setKeyId(key.getKeyId())
        .build();
  }

  /**
   * Validates a {@code key}.
   *
   * @throws GeneralSecurityException if {@code key} is invalid.
   */
  public static void validateKey(Keyset.Key key) throws GeneralSecurityException {
    if (!key.hasKeyData()) {
      throw new GeneralSecurityException(String.format("key %d has no key data", key.getKeyId()));
    }

    if (key.getOutputPrefixType() == OutputPrefixType.UNKNOWN_PREFIX) {
      throw new GeneralSecurityException(
          String.format("key %d has unknown prefix", key.getKeyId()));
    }

    if (key.getStatus() == KeyStatusType.UNKNOWN_STATUS) {
      throw new GeneralSecurityException(
          String.format("key %d has unknown status", key.getKeyId()));
    }
  }

  /**
   * Validates a {@code Keyset}.
   *
   * @throws GeneralSecurityException if {@code keyset} is invalid.
   */
  public static void validateKeyset(Keyset keyset) throws GeneralSecurityException {
    int primaryKeyId = keyset.getPrimaryKeyId();
    boolean hasPrimaryKey = false;
    boolean containsOnlyPublicKeyMaterial = true;
    int numEnabledKeys = 0;
    for (Keyset.Key key : keyset.getKeyList()) {
      if (key.getStatus() != KeyStatusType.ENABLED) {
        continue;
      }
      validateKey(key);
      if (key.getKeyId() == primaryKeyId) {
        if (hasPrimaryKey) {
          throw new GeneralSecurityException("keyset contains multiple primary keys");
        }
        hasPrimaryKey = true;
      }
      if (key.getKeyData().getKeyMaterialType() != KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC) {
        containsOnlyPublicKeyMaterial = false;
      }
      numEnabledKeys++;
    }
    if (numEnabledKeys == 0) {
      throw new GeneralSecurityException("keyset must contain at least one ENABLED key");
    }
    // Checks that a keyset contains a primary key, except when it contains only public keys.
    if (!hasPrimaryKey && !containsOnlyPublicKeyMaterial) {
      throw new GeneralSecurityException("keyset doesn't contain a valid primary key");
    }
  }

  /**
   * Reads all bytes from {@code inputStream}.
   */
  public static byte[] readAll(InputStream inputStream) throws IOException {
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    int count;
    while ((count = inputStream.read(buf)) != -1) {
      result.write(buf, 0, count);
    }
    return result.toByteArray();
  }

  private Util() {}
}
