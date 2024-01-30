// Copyright 2024 Google LLC
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

package com.google.crypto.tink.signature.internal.testing;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/** A KeyManager for a PublicKeySign primitive for testing. */
public final class LegacyPublicKeySignKeyManager implements PrivateKeyManager<PublicKeySign> {
  private static final String TYPE_URL = "type.googleapis.com/custom.Ed25519PrivateKey";

  @AccessesPartialKey
  private static com.google.crypto.tink.signature.Ed25519PrivateKey parsePrivateKey(
      Ed25519PrivateKey protoKey) throws GeneralSecurityException {
    com.google.crypto.tink.signature.Ed25519PublicKey publicKey =
        LegacyPublicKeyVerifyKeyManager.parsePublicKey(protoKey.getPublicKey());
    return com.google.crypto.tink.signature.Ed25519PrivateKey.create(
        publicKey,
        SecretBytes.copyFrom(protoKey.getKeyValue().toByteArray(), InsecureSecretKeyAccess.get()));
  }

  @Override
  public PublicKeySign getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      Ed25519PrivateKey keyProto =
          Ed25519PrivateKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return Ed25519Sign.create(parsePrivateKey(keyProto));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized Ed25519PrivateKey proto", e);
    }
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<PublicKeySign> getPrimitiveClass() {
    return PublicKeySign.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(keyPair.getPublicKey()))
            .build();
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(keyPair.getPrivateKey()))
            .setPublicKey(publicKey)
            .build();
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(privateKey.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
        .build();
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      Ed25519PrivateKey keyProto =
          Ed25519PrivateKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return KeyData.newBuilder()
          .setTypeUrl(LegacyPublicKeyVerifyKeyManager.TYPE_URL)
          .setValue(keyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized Ed25519PrivateKey proto", e);
    }
  }
}
