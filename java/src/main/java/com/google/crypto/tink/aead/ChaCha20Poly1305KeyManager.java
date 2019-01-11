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
import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.proto.ChaCha20Poly1305Key;
import com.google.crypto.tink.proto.Empty;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This instance of {@code KeyManager} generates new {@code ChaCha20Poly1305} keys and produces new
 * instances of {@code ChaCha20Poly1305}.
 */
class ChaCha20Poly1305KeyManager
    extends KeyManagerBase<Aead, ChaCha20Poly1305Key, Empty> {
  public ChaCha20Poly1305KeyManager() {
    super(Aead.class, ChaCha20Poly1305Key.class, Empty.class, TYPE_URL);
  }

  /** Type url that this manager supports */
  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

  private static final int KEY_SIZE_IN_BYTES = 32;

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public Aead getPrimitiveFromKey(ChaCha20Poly1305Key keyProto) throws GeneralSecurityException {
    return new ChaCha20Poly1305(keyProto.getKeyValue().toByteArray());
  }

  @Override
  protected ChaCha20Poly1305Key newKeyFromFormat(Empty unused) throws GeneralSecurityException {
    return ChaCha20Poly1305Key.newBuilder()
        .setVersion(VERSION)
        .setKeyValue(ByteString.copyFrom(Random.randBytes(KEY_SIZE_IN_BYTES)))
        .build();
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  protected ChaCha20Poly1305Key parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return ChaCha20Poly1305Key.parseFrom(byteString);
  }

  @Override
  protected Empty parseKeyFormatProto(ByteString byteString) throws InvalidProtocolBufferException {
    return Empty.parseFrom(byteString);
  }

  @Override
  protected void validateKey(ChaCha20Poly1305Key keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    if (keyProto.getKeyValue().size() != KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("invalid ChaCha20Poly1305Key: incorrect key length");
    }
  }

  @Override
  protected void validateKeyFormat(Empty unused) throws GeneralSecurityException {}
}
