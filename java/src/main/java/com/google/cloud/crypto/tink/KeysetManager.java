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

import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.Random;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Manages a Keyset-proto, with convenience methods that rotate, disable, enable or
 * destroy keys.
 * Not thread-safe.
 */
public class KeysetManager {
  private final Keyset.Builder keysetBuilder;
  private final KeyFormat keyFormat;
  private final OutputPrefixType outputPrefixType;

  private KeysetManager(Builder builder) {
    keyFormat = builder.keyFormat;
    outputPrefixType = builder.outputPrefixType;

    if (builder.keysetHandle != null) {
      keysetBuilder = builder.keysetHandle.getKeyset().toBuilder();
    } else {
      keysetBuilder = Keyset.newBuilder();
    }
  }

  /**
   * Builder for KeysetManager.
   */
  public static class Builder {
    private OutputPrefixType outputPrefixType = OutputPrefixType.TINK;
    private KeyFormat keyFormat = null;
    private KeysetHandle keysetHandle = null;

    public Builder() {
    }


    public Builder setOutputPrefixType(OutputPrefixType val) {
      outputPrefixType = val;
      return this;
    }

    public Builder setKeysetHandle(KeysetHandle val) {
      keysetHandle = val;
      return this;
    }

    public Builder setKeyFormat(KeyFormat val) {
      keyFormat = val;
      return this;
    }

    public KeysetManager build() {
      return new KeysetManager(this);
    }
  }

  /**
   * Rotates a keyset by generating a fresh key using a key format.
   * Setting the new key as the primary key.
   */
  public KeysetManager rotate() throws GeneralSecurityException {
    if (keyFormat != null) {
      return rotate(keyFormat);
    } else {
      throw new GeneralSecurityException("cannot rotate, needs key format");
    }
  }

  /**
   * Rotates a keyset by generating a fresh key using {@code keyFormat}.
   * Setting the new key as the primary key.
   */
  public KeysetManager rotate(KeyFormat keyFormat) throws GeneralSecurityException {
    KeyData keyData = Registry.INSTANCE.newKey(keyFormat);
    int keyId = Random.randNonNegativeInt();
    while (hasKeyWithKeyId(keyId)) {
      keyId = Random.randNonNegativeInt();
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
  public KeysetHandle getKeysetHandle() {
    return new KeysetHandle(keysetBuilder.build());
  }

  /**
   * Encrypts the managed keyset with {@code aead} and returns a {@code KeysetHandle} of
   * the encrypted result.
   * @return a {@code KeysetHandle} of an encrypted keyset.
   * @throws GeneralSecurityException
   */
  public KeysetHandle getKeysetHandle(Aead aead) throws GeneralSecurityException {
    Keyset keyset = keysetBuilder.build();
    byte[] encryptedKeyset = aead.encrypt(keyset.toByteArray(), null /* aad */);
    // Check if we can decrypt encryptedKeyset, to detect errors
    try {
      byte[] cleartext = aead.decrypt(encryptedKeyset, null /* aad */);
      Keyset keyset2 = Keyset.parseFrom(cleartext);
      if (!keyset2.equals(keyset)) {
        throw new GeneralSecurityException("encryption with KMS failed");
      }
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("encryption with KMS failed");
    }

    return new KeysetHandle(keyset, encryptedKeyset);
  }

  private boolean hasKeyWithKeyId(int keyId) {
    for (Keyset.Key key : keysetBuilder.getKeyList()) {
      if (key.getKeyId() == keyId) {
        return true;
      }
    }
    return false;
  }
}
