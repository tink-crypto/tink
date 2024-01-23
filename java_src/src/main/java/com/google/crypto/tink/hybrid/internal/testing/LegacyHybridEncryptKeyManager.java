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
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.internal.BigIntegerEncoding;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

/** A KeyManager for HPKE Encrypt with a custom type URL for testing. */
public final class LegacyHybridEncryptKeyManager implements KeyManager<HybridEncrypt> {
  static final String TYPE_URL = "type.googleapis.com/custom.HpkePublicKey";

  @AccessesPartialKey
  static com.google.crypto.tink.hybrid.HpkePublicKey parsePublicKey(HpkePublicKey protoKey)
      throws GeneralSecurityException {
    if (protoKey.getVersion() != 0) {
      throw new GeneralSecurityException("Only version 0 keys are accepted");
    }
    if (protoKey.getParams().getKem() != HpkeKem.DHKEM_X25519_HKDF_SHA256) {
      throw new GeneralSecurityException("Only HpkeKem.DHKEM_X25519_HKDF_SHA256 is supported");
    }
    if (protoKey.getParams().getKdf() != HpkeKdf.HKDF_SHA256) {
      throw new GeneralSecurityException("Only HpkeKdf.HKDF_SHA256 is supported");
    }
    if (protoKey.getParams().getAead() != HpkeAead.AES_128_GCM) {
      throw new GeneralSecurityException("Only HpkeAead.AES_128_GCM is supported");
    }
    HpkeParameters parameters =
        HpkeParameters.builder()
            .setVariant(HpkeParameters.Variant.NO_PREFIX)
            .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
            .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
            .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
            .build();
    BigInteger n =
        BigIntegerEncoding.fromUnsignedBigEndianBytes(protoKey.getPublicKey().toByteArray());
    byte[] encodedPublicKeyBytes = BigIntegerEncoding.toBigEndianBytesOfFixedLength(n, 32);
    return com.google.crypto.tink.hybrid.HpkePublicKey.create(
        parameters, Bytes.copyFrom(encodedPublicKeyBytes), /* idRequirement= */ null);
  }

  @Override
  public HybridEncrypt getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      com.google.crypto.tink.proto.HpkePublicKey protoKey =
          com.google.crypto.tink.proto.HpkePublicKey.parseFrom(
              serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return HpkeEncrypt.create(parsePublicKey(protoKey));
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized HpkePublicKey proto", e);
    }
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<HybridEncrypt> getPrimitiveClass() {
    return HybridEncrypt.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }
}
