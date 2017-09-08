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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.proto.ChaCha20Poly1305Key;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.DjbCipher;
import com.google.crypto.tink.subtle.DjbCipherPoly1305;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * This instance of {@code KeyManager} generates new {@code ChaCha20Poly1305} keys and produces new
 * instances of {@code ChaCha20Poly1305}.
 */
class ChaCha20Poly1305KeyManager implements KeyManager<Aead> {
  /** Type url that this manager supports */
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      ChaCha20Poly1305Key keyProto = ChaCha20Poly1305Key.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid ChaCha20Poly1305 key", e);
    }
  }

  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof ChaCha20Poly1305Key)) {
      throw new GeneralSecurityException("expected ChaCha20Poly1305Key proto");
    }
    ChaCha20Poly1305Key keyProto = (ChaCha20Poly1305Key) key;
    validateKey(keyProto);
    return DjbCipherPoly1305.constructChaCha20Poly1305Ietf(keyProto.getKeyValue().toByteArray());
  }

  @Override
  public MessageLite newKey(ByteString unused) throws GeneralSecurityException {
    return newKey();
  }

  @Override
  public MessageLite newKey(MessageLite unused) throws GeneralSecurityException {
    return newKey();
  }

  @Override
  public KeyData newKeyData(ByteString unused) throws GeneralSecurityException {
    ChaCha20Poly1305Key key = newKey();
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
        .build();
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return TYPE_URL.equals(typeUrl);
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  private ChaCha20Poly1305Key newKey() throws GeneralSecurityException {
    return ChaCha20Poly1305Key.newBuilder()
        .setVersion(VERSION)
        .setKeyValue(ByteString.copyFrom(Random.randBytes(DjbCipher.KEY_SIZE_IN_BYTES)))
        .build();
  }

  private void validateKey(ChaCha20Poly1305Key keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    if (keyProto.getKeyValue().size() != DjbCipher.KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("invalid ChaCha20Poly1305Key: incorrect key length");
    }
  }
}
