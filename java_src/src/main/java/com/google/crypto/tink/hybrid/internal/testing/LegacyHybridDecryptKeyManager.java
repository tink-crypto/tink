// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal.testing;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/** A KeyManager for HybridDecrypt with a custom type URL for testing. */
public class LegacyHybridDecryptKeyManager implements PrivateKeyManager<HybridDecrypt> {

  private static final String TYPE_URL = "type.googleapis.com/custom.HpkePrivateKey";

  @AccessesPartialKey
  private static com.google.crypto.tink.hybrid.HpkePrivateKey parsePrivateKey(
      HpkePrivateKey protoKey) throws GeneralSecurityException {
    HpkePublicKey publicKey = LegacyHybridEncryptKeyManager.parsePublicKey(protoKey.getPublicKey());
    return com.google.crypto.tink.hybrid.HpkePrivateKey.create(
        publicKey,
        SecretBytes.copyFrom(
            protoKey.getPrivateKey().toByteArray(), InsecureSecretKeyAccess.get()));
  }

  @Override
  public HybridDecrypt getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      HpkePrivateKey keyProto =
          HpkePrivateKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return HpkeDecrypt.create(parsePrivateKey(keyProto));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized HpkePrivateKey proto", e);
    }
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<HybridDecrypt> getPrimitiveClass() {
    return HybridDecrypt.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }

  @Override
  public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
    try {
      HpkePrivateKey keyProto =
          HpkePrivateKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return KeyData.newBuilder()
          .setTypeUrl(LegacyHybridEncryptKeyManager.TYPE_URL)
          .setValue(keyProto.getPublicKey().toByteString())
          .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized HpkePrivateKey proto", e);
    }
  }
}
