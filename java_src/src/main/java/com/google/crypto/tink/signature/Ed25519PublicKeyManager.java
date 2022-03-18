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

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code Ed25519Verify}. It doesn't support key
 * generation.
 */
class Ed25519PublicKeyManager extends KeyTypeManager<Ed25519PublicKey> {
  public Ed25519PublicKeyManager() {
    super(
        Ed25519PublicKey.class,
        new KeyTypeManager.PrimitiveFactory<PublicKeyVerify, Ed25519PublicKey>(
            PublicKeyVerify.class) {
          @Override
          public PublicKeyVerify getPrimitive(Ed25519PublicKey keyProto) {
            return new Ed25519Verify(keyProto.getKeyValue().toByteArray());
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PUBLIC;
  }

  @Override
  public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return Ed25519PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(Ed25519PublicKey keyProto) throws GeneralSecurityException {
    Validators.validateVersion(keyProto.getVersion(), getVersion());
    if (keyProto.getKeyValue().size() != Ed25519Verify.PUBLIC_KEY_LEN) {
      throw new GeneralSecurityException("invalid Ed25519 public key: incorrect key length");
    }
  }
}
