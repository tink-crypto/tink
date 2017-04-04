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

package com.google.cloud.crypto.tink.aead;

import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKey;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKeyFormat;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrParams;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.subtle.AesCtrJceCipher;
import com.google.cloud.crypto.tink.subtle.IndCpaCipher;
import com.google.cloud.crypto.tink.subtle.Random;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

class AesCtrKeyManager implements KeyManager<IndCpaCipher, AesCtrKey, AesCtrKeyFormat> {
  private static final int VERSION = 0;

  private static final String AES_CTR_KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.AesCtrKey";

  // In counter mode each message is encrypted with an initialization vector (IV) that must be
  // unique. If one single IV is ever used to encrypt two or more messages, the confidentiality of
  // these messages might be lost. This cipher uses a randomly generated IV for each message. The
  // birthday paradox says that if one encrypts 2^k messages, the probability that the random IV
  // will repeat is roughly 2^{2k - t}, where t is the size in bits of the IV. Thus with 96-bit
  // (12-byte) IV, if one encrypts 2^32 messages the probability of IV collision is less than
  // 2^-33 (i.e., less than one in eight billion).
  private static final int MIN_IV_SIZE_IN_BYTES = 12;

  @Override
  public AesCtrJceCipher getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      AesCtrKey keyProto = AesCtrKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesCtr Key");
    }
  }

  @Override
  public AesCtrJceCipher getPrimitive(AesCtrKey keyProto) throws GeneralSecurityException {
    validate(keyProto);
    return new AesCtrJceCipher(keyProto.getKeyValue().toByteArray(),
        keyProto.getParams().getIvSize());
  }

  @Override
  public AesCtrKey newKey(ByteString serialized) throws GeneralSecurityException {
    try {
      AesCtrKeyFormat format = AesCtrKeyFormat.parseFrom(serialized);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesCtr key format", e);
    }
  }

  @Override
  public AesCtrKey newKey(AesCtrKeyFormat format) throws GeneralSecurityException {
    validate(format);
    return AesCtrKey.newBuilder()
        .setParams(format.getParams())
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setVersion(VERSION)
        .build();
  }

  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    AesCtrKey key = newKey(serialized);
    return KeyData.newBuilder()
        .setTypeUrl(AES_CTR_KEY_TYPE)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
        .build();
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(AES_CTR_KEY_TYPE);
  }

  private void validate(AesCtrKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
    SubtleUtil.validateAesKeySize(key.getKeyValue().size());
    validate(key.getParams());
  }

  private void validate(AesCtrKeyFormat format) throws GeneralSecurityException {
    SubtleUtil.validateAesKeySize(format.getKeySize());
    validate(format.getParams());
  }

  private void validate(AesCtrParams params) throws GeneralSecurityException {
    if (params.getIvSize() < MIN_IV_SIZE_IN_BYTES || params.getIvSize() > 16) {
      throw new GeneralSecurityException("invalid IV size");
    }
  }
}
