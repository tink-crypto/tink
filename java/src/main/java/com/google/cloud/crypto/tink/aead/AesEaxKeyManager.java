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
import com.google.cloud.crypto.tink.AesEaxProto.AesEaxKey;
import com.google.cloud.crypto.tink.AesEaxProto.AesEaxKeyFormat;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.subtle.AesEaxJce;
import com.google.cloud.crypto.tink.subtle.Random;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

class AesEaxKeyManager implements KeyManager<Aead, AesEaxKey, AesEaxKeyFormat> {
  private static final int VERSION = 0;

  private static final String KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.AesEaxKey";

  @Override
  public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      AesEaxKey keyProto = AesEaxKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesEax key");
    }
  }

  @Override
  public Aead getPrimitive(AesEaxKey keyProto) throws GeneralSecurityException {
    validate(keyProto);
    return new AesEaxJce(keyProto.getKeyValue().toByteArray(), keyProto.getParams().getIvSize());
  }

  @Override
  public AesEaxKey newKey(ByteString serialized) throws GeneralSecurityException {
    try {
      AesEaxKeyFormat format = AesEaxKeyFormat.parseFrom(serialized);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid AesEax key format", e);
    }
  }

  @Override
  public AesEaxKey newKey(AesEaxKeyFormat format) throws GeneralSecurityException {
    validate(format);
    return AesEaxKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    AesEaxKey key = newKey(serialized);
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

  private void validate(AesEaxKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
    SubtleUtil.validateAesKeySize(key.getKeyValue().size());
    if (key.getParams().getIvSize() != 12 && key.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }

  private void validate(AesEaxKeyFormat format) throws GeneralSecurityException {
    SubtleUtil.validateAesKeySize(format.getKeySize());
    if (format.getParams().getIvSize() != 12 && format.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }
}
