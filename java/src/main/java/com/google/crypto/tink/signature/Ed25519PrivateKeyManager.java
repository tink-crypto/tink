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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.Empty;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This instance of {@code KeyManager} generates new {@code Ed25519PrivateKey} keys and produces new
 * instances of {@code Ed25519Sign}.
 */
class Ed25519PrivateKeyManager
    extends KeyManagerBase<PublicKeySign, Ed25519PrivateKey, Empty>
    implements PrivateKeyManager<PublicKeySign> {
  public Ed25519PrivateKeyManager() {
    super(PublicKeySign.class, Ed25519PrivateKey.class, Empty.class, TYPE_URL);
  }

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

  private static final int VERSION = 0;

  @Override
  public PublicKeySign getPrimitiveFromKey(Ed25519PrivateKey keyProto)
      throws GeneralSecurityException {
    return new Ed25519Sign(keyProto.getKeyValue().toByteArray());
  }

  @Override
  public Ed25519PrivateKey newKeyFromFormat(Empty unused) throws GeneralSecurityException {
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(VERSION)
            .setKeyValue(ByteString.copyFrom(keyPair.getPublicKey()))
            .build();
    return Ed25519PrivateKey.newBuilder()
        .setVersion(VERSION)
        .setKeyValue(ByteString.copyFrom(keyPair.getPrivateKey()))
        .setPublicKey(publicKey)
        .build();
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      Ed25519PrivateKey privKeyProto = Ed25519PrivateKey.parseFrom(serializedKey);
      return KeyData.newBuilder()
          .setTypeUrl(Ed25519PublicKeyManager.TYPE_URL)
          .setValue(privKeyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized Ed25519PrivateKey proto", e);
    }
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  protected Ed25519PrivateKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return Ed25519PrivateKey.parseFrom(byteString);
  }

  @Override
  protected Empty parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return Empty.parseFrom(byteString);
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected void validateKey(Ed25519PrivateKey keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    if (keyProto.getKeyValue().size() != Ed25519Sign.SECRET_KEY_LEN) {
      throw new GeneralSecurityException("invalid Ed25519 private key: incorrect key length");
    }
  }

  @Override
  protected void validateKeyFormat(Empty unused) {}
}
