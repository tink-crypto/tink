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

import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKey;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKeyFormat;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.subtle.AesGcmJce;
import com.google.cloud.crypto.tink.subtle.Random;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

class AesGcmKeyManager implements KeyManager<Aead, AesGcmKey, AesGcmKeyFormat> {
  private static final int VERSION = 0;

  private static final String KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";

  @Override
  public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      AesGcmKey keyProto = AesGcmKey.parseFrom(serialized);
      return new AesGcmJce(keyProto.getKeyValue().toByteArray());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesGcm key");
    }
  }

  @Override
  public Aead getPrimitive(AesGcmKey keyProto) throws GeneralSecurityException {
    validate(keyProto);
    return new AesGcmJce(keyProto.getKeyValue().toByteArray());
  }

  @Override
  public AesGcmKey newKey(ByteString serialized) throws GeneralSecurityException {
    try {
      AesGcmKeyFormat format = AesGcmKeyFormat.parseFrom(serialized);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesGcm key format", e);
    }
  }

  @Override
  public AesGcmKey newKey(AesGcmKeyFormat format) throws GeneralSecurityException {
    validate(format);
    return AesGcmKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    AesGcmKey key = newKey(serialized);
    return KeyData.newBuilder()
        .setTypeUrl(KEY_TYPE)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.SYMMETRIC)
        .build();
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(KEY_TYPE);
  }

  private void validate(AesGcmKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
    SubtleUtil.validateAesKeySize(key.getKeyValue().size());
  }

  private void validate(AesGcmKeyFormat format) throws GeneralSecurityException {
    SubtleUtil.validateAesKeySize(format.getKeySize());
  }
}
