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

package com.google.cloud.crypto.tink.aead; // instead of subtle, because it depends on KeyFormat.

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.KmsEnvelopeProto.KmsEnvelopePayload;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.Registry;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.concurrent.Future;

/**
 * This primitive implements <a href="https://cloud.google.com/kms/docs/data-encryption-keys">
 * envelope encryption</a>. In envelope encryption, user generates a data encryption key (DEK)
 * locally, encrypts data with DEK, sends DEK to a KMS to be encrypted (with a key managed by KMS),
 * and stores encrypted DEK with encrypted data; at a later point user can retrieve encrypted data
 * and DEK, use Storky to decrypt DEK, and use decrypted DEK to decrypt the data.
 */
class KmsEnvelopeAead implements Aead {
  private final KeyFormat dekFormat;
  private final Aead remote;

  KmsEnvelopeAead(KeyFormat dekFormat, Aead remote) {
    this.dekFormat = dekFormat;
    this.remote = remote;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] aad) throws GeneralSecurityException {
    // Generate a new DEK.
    Any dek = Registry.INSTANCE.newKey(dekFormat);
    // Wrap it with remote.
    byte[] encryptedDek = remote.encrypt(dek.toByteArray(), null /* aad */);
    // Use DEK to encrypt plaintext.
    Aead aead = Registry.INSTANCE.getPrimitive(dek);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    // Build ciphertext protobuf and return result.
    return KmsEnvelopePayload.newBuilder()
        .setEncryptedDek(ByteString.copyFrom(encryptedDek))
        .setCiphertext(ByteString.copyFrom(ciphertext))
        .build()
        .toByteArray();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] aad)
      throws GeneralSecurityException {
    try {
      KmsEnvelopePayload proto = KmsEnvelopePayload.parseFrom(ciphertext);
      byte[] encryptedDek = proto.getEncryptedDek().toByteArray();
      // Use remote to decrypt encryptedDek.
      Any dek = Any.parseFrom(remote.decrypt(encryptedDek, null /* aad */));
      // Use DEK to decrypt ciphertext.
      Aead aead = Registry.INSTANCE.getPrimitive(dek);
      return aead.decrypt(proto.getCiphertext().toByteArray(), aad);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("decryption failed");
    }
  }

  @Override
  public Future<byte[]> asyncEncrypt(final byte[] plaintext, final byte[] aad)
      throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented Yet!");
  }

  @Override
  public Future<byte[]> asyncDecrypt(final byte[] ciphertext, final byte[] aad)
      throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented Yet!");
  }
}
