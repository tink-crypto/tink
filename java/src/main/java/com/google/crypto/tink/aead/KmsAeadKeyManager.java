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
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KmsAeadKey;
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code Aead} that forwards encrypt/decrypt requests to
 * a key residing in a remote KMS.
 */
class KmsAeadKeyManager extends KeyManagerBase<Aead, KmsAeadKey, KmsAeadKeyFormat> {
  public KmsAeadKeyManager() {
    super(Aead.class, KmsAeadKey.class, KmsAeadKeyFormat.class, TYPE_URL);
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsAeadKey";

  @Override
  public Aead getPrimitiveFromKey(KmsAeadKey keyProto) throws GeneralSecurityException {
    String keyUri = keyProto.getParams().getKeyUri();
    KmsClient kmsClient = KmsClients.get(keyUri);
    return kmsClient.getAead(keyUri);
  }

  @Override
  public KmsAeadKey newKeyFromFormat(KmsAeadKeyFormat format) throws GeneralSecurityException {
    return KmsAeadKey.newBuilder().setParams(format).setVersion(VERSION).build();
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  protected KeyMaterialType keyMaterialType() {
    return KeyMaterialType.REMOTE;
  }

  @Override
  protected KmsAeadKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return KmsAeadKey.parseFrom(byteString);
  }

  @Override
  protected KmsAeadKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return KmsAeadKeyFormat.parseFrom(byteString);
  }

  @Override
  protected void validateKey(KmsAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
  }

  @Override
  protected void validateKeyFormat(KmsAeadKeyFormat format) {}
}
