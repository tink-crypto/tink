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

import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * This instance of {@code KeyManager} generates new {@code Ed25519PrivateKey} keys and produces new
 * instances of {@code Ed25519Sign}.
 */
class Ed25519PrivateKeyManager implements PrivateKeyManager<PublicKeySign> {
  /** Type url that this manager supports */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

  /** Current version of this key manager. Keys with greater version are not supported. */
  private static final int VERSION = 0;

  @Override
  public PublicKeySign getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      Ed25519PrivateKey keyProto = Ed25519PrivateKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid Ed25519 private key", e);
    }
  }

  @Override
  public PublicKeySign getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof Ed25519PrivateKey)) {
      throw new GeneralSecurityException("expected Ed25519PrivateKey proto");
    }
    Ed25519PrivateKey keyProto = (Ed25519PrivateKey) key;
    validateKey(keyProto);
    return new Ed25519Sign(keyProto.getKeyValue().toByteArray());
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
    Ed25519PrivateKey key = newKey();
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
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

  private Ed25519PrivateKey newKey() throws GeneralSecurityException {
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

  private void validateKey(Ed25519PrivateKey keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), VERSION);
    if (keyProto.getKeyValue().size() != Ed25519Sign.SECRET_KEY_LEN) {
      throw new GeneralSecurityException("invalid Ed25519 private key: incorrect key length");
    }
  }
}
