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
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/** A KeyManager for a PublicKeyVerify primitive for testing. */
public final class LegacyPublicKeyVerifyKeyManager implements KeyManager<PublicKeyVerify> {
  static final String TYPE_URL = "type.googleapis.com/custom.Ed25519PublicKey";

  @AccessesPartialKey
  static com.google.crypto.tink.signature.Ed25519PublicKey parsePublicKey(Ed25519PublicKey protoKey)
      throws GeneralSecurityException {
    if (protoKey.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 keys are accepted");
    }
    return com.google.crypto.tink.signature.Ed25519PublicKey.create(
        Bytes.copyFrom(protoKey.getKeyValue().toByteArray()));
  }

  @Override
  public PublicKeyVerify getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      com.google.crypto.tink.proto.Ed25519PublicKey protoKey =
          com.google.crypto.tink.proto.Ed25519PublicKey.parseFrom(
              serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return Ed25519Verify.create(parsePublicKey(protoKey));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized Ed25519PublicKey proto", e);
    }
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<PublicKeyVerify> getPrimitiveClass() {
    return PublicKeyVerify.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }
}
