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

/**
 * Manages a Keyset-proto, with convenience methods that rotate, disable, enable or
 * destroy keys.
 * Not thread-safe.
 */
public class KeysetManager {
  private final Keyset.Builder keysetBuilder;

  private KeysetManager(Keyset.Builder val) {
    keysetBuilder = val;
  }

  /**
   * Gets a keyset manager from an existing keyset handle.
   */
  public static KeysetManager fromKeysetHandle(KeysetHandle val) {
    return new KeysetManager(val.getKeyset().toBuilder());
  }

  /**
   * Gets a keyset manager with an empty keyset.
   */
  public static KeysetManager withEmptyKeyset() {
    return new KeysetManager(Keyset.newBuilder());
  }

  /**
   * Rotates a keyset by generating a fresh key using {@code keyTemplate}.
   * Setting the new key as the primary key.
   */
  public KeysetManager rotate(KeyTemplate keyTemplate) throws GeneralSecurityException {
    KeyData keyData = Registry.newKeyData(keyTemplate);
    int keyId = newKeyId();
    OutputPrefixType outputPrefixType = keyTemplate.getOutputPrefixType();
    if (outputPrefixType == OutputPrefixType.UNKNOWN_PREFIX) {
      outputPrefixType = OutputPrefixType.TINK;
    }
    Keyset.Key key = Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setKeyId(keyId)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(outputPrefixType)
        .build();
    keysetBuilder.addKey(key).setPrimaryKeyId(key.getKeyId());
    return this;
  }

  /**
   * @return return {@code KeysetHandle} of the managed keyset.
   */
  public KeysetHandle getKeysetHandle() throws GeneralSecurityException {
    return KeysetHandle.fromKeyset(keysetBuilder.build());
  }

  private int newKeyId() {
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

  /**
   * @return positive random int.
   */
  private static int randPositiveInt() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] rand = new byte[4];
    int result = 0;
    while (result == 0) {
      secureRandom.nextBytes(rand);
      result = ((rand[0] & 0x7f) << 24)
          | ((rand[1] & 0xff) << 16)
          | ((rand[2] & 0xff) << 8)
          | (rand[3] & 0xff);
    }
    return result;
  }
}
