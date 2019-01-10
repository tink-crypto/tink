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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyManagerBase;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * This key manager generates new {@code AesSivKey} keys and produces new instances of {@code
 * AesSiv}.
 */
class AesSivKeyManager extends KeyManagerBase<DeterministicAead, AesSivKey, AesSivKeyFormat> {
  public AesSivKeyManager() {
    super(DeterministicAead.class, AesSivKey.class, AesSivKeyFormat.class, TYPE_URL);
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.AesSivKey";

  @Override
  protected DeterministicAead getPrimitiveFromKey(AesSivKey keyProto)
      throws GeneralSecurityException {
    return new AesSiv(keyProto.getKeyValue().toByteArray());
  }

  @Override
  public AesSivKey newKeyFromFormat(AesSivKeyFormat format) throws GeneralSecurityException {
    return AesSivKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
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
  protected AesSivKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesSivKey.parseFrom(byteString);
  }

  @Override
  protected AesSivKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return AesSivKeyFormat.parseFrom(byteString);
  }

  @Override
  protected void validateKey(AesSivKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() != 64) {
      throw new InvalidKeyException(
          "invalid key size: " + key.getKeyValue().size() + ". Valid keys must have 64 bytes.");
    }
  }

  @Override
  protected void validateKeyFormat(AesSivKeyFormat format) throws GeneralSecurityException {
    if (format.getKeySize() != 64) {
      throw new InvalidAlgorithmParameterException(
          "invalid key size: " + format.getKeySize() + ". Valid keys must have 64 bytes.");
    }
  }
}
