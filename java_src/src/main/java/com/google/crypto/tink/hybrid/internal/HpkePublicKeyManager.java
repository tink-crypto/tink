// Copyright 2021 Google LLC
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

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/** Key manager that produces new instances of {@link HpkeEncrypt} primitive. */
public final class HpkePublicKeyManager extends KeyTypeManager<HpkePublicKey> {
  public HpkePublicKeyManager() {
    super(
        HpkePublicKey.class,
        new KeyTypeManager.PrimitiveFactory<HybridEncrypt, HpkePublicKey>(HybridEncrypt.class) {
          @Override
          public HybridEncrypt getPrimitive(HpkePublicKey recipientPublicKey)
              throws GeneralSecurityException {
            return HpkeEncrypt.createHpkeEncrypt(recipientPublicKey);
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HpkePublicKey";
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
  public HpkePublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return HpkePublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(HpkePublicKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    if (!key.hasParams()) {
      throw new GeneralSecurityException("Missing HPKE key params.");
    }
    validateParams(key.getParams());
  }

  private void validateParams(HpkeParams params) throws GeneralSecurityException {
    if ((params.getKem() == HpkeKem.KEM_UNKNOWN) || (params.getKem() == HpkeKem.UNRECOGNIZED)) {
      throw new GeneralSecurityException("Invalid KEM param: " + params.getKem().name());
    }
    if ((params.getKdf() == HpkeKdf.KDF_UNKNOWN) || (params.getKdf() == HpkeKdf.UNRECOGNIZED)) {
      throw new GeneralSecurityException("Invalid KDF param: " + params.getKdf().name());
    }
    if ((params.getAead() == HpkeAead.AEAD_UNKNOWN)
        || (params.getAead() == HpkeAead.UNRECOGNIZED)) {
      throw new GeneralSecurityException("Invalid AEAD param: " + params.getAead().name());
    }
  }
}
