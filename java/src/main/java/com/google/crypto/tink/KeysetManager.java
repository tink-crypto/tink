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
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Manages a Keyset-proto, with convenience methods that rotate, disable, enable or
 * destroy keys.
 * Not thread-safe.
 */
public class KeysetManager {
  private final Keyset.Builder keysetBuilder;
  private final KeyTemplate keyTemplate;
  private final OutputPrefixType outputPrefixType;
  private final Aead masterKey;

  private KeysetManager(Builder builder) {
    keyTemplate = builder.keyTemplate;
    outputPrefixType = builder.outputPrefixType;
    masterKey = builder.masterKey;

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
    private KeyTemplate keyTemplate = null;
    private KeysetHandle keysetHandle = null;
    private Aead masterKey = null;

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

    public Builder setMasterKey(Aead val) {
      masterKey = val;
      return this;
    }

    public Builder setKeyTemplate(KeyTemplate val) {
      keyTemplate = val;
      return this;
    }

    public KeysetManager build() {
      return new KeysetManager(this);
    }
  }

  /**
   * Rotates a keyset by generating a fresh key using a key template.
   * Setting the new key as the primary key.
   */
  public KeysetManager rotate() throws GeneralSecurityException {
    if (keyTemplate != null) {
      return rotate(keyTemplate);
    } else {
      throw new GeneralSecurityException("cannot rotate, needs key template");
    }
  }

  /**
   * Rotates a keyset by generating a fresh key using {@code keyTemplate}.
   * Setting the new key as the primary key.
   */
  public KeysetManager rotate(KeyTemplate keyTemplate) throws GeneralSecurityException {
    KeyData keyData = Registry.INSTANCE.newKeyData(keyTemplate);
    int keyId = Random.randPositiveInt();
    while (hasKeyWithKeyId(keyId)) {
      keyId = Random.randPositiveInt();
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
    if (masterKey == null) {
      return new KeysetHandle(keysetBuilder.build());
    }
    Keyset keyset = keysetBuilder.build();
    byte[] encryptedKeyset = masterKey.encrypt(keyset.toByteArray(),
        /* additionalData= */new byte[0]);
    // Check if we can decrypt, to detect errors
    try {
      final Keyset keyset2 = Keyset.parseFrom(masterKey.decrypt(
          encryptedKeyset, /* additionalData= */new byte[0]));
      if (!keyset2.equals(keyset)) {
        throw new GeneralSecurityException("cannot encrypt keyset");
      }
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset, corrupted key material");
    }
    EncryptedKeyset proto = EncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
        .setKeysetInfo(Util.getKeysetInfo(keyset))
        .build();
    return new KeysetHandle(keyset, proto);
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
