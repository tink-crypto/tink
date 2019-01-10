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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code AesEaxKey} keys and produces new instances of {@code
 * AesEaxJce}.
 */
class AesEaxKeyManager extends KeyManagerBase<Aead, AesEaxKey, AesEaxKeyFormat> {
  public AesEaxKeyManager() {
    super(Aead.class, AesEaxKey.class, AesEaxKeyFormat.class, TYPE_URL);
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesEaxKey";

  @Override
  public Aead getPrimitiveFromKey(AesEaxKey keyProto) throws GeneralSecurityException {
    return new AesEaxJce(keyProto.getKeyValue().toByteArray(), keyProto.getParams().getIvSize());
  }

  @Override
  public AesEaxKey newKeyFromFormat(AesEaxKeyFormat format) throws GeneralSecurityException {
    return AesEaxKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  protected AesEaxKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesEaxKey.parseFrom(byteString);
  }

  @Override
  protected AesEaxKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesEaxKeyFormat.parseFrom(byteString);
  }

  @Override
  protected void validateKey(AesEaxKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    Validators.validateAesKeySize(key.getKeyValue().size());
    if (key.getParams().getIvSize() != 12 && key.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }

  @Override
  protected void validateKeyFormat(AesEaxKeyFormat format) throws GeneralSecurityException {
    Validators.validateAesKeySize(format.getKeySize());
    if (format.getParams().getIvSize() != 12 && format.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }
}
