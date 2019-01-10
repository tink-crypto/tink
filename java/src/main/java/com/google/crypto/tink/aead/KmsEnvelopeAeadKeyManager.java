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
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code KmsEnvelopeAeadKey} keys and produces new instances of
 * {@code KmsEnvelopeAead}.
 */
class KmsEnvelopeAeadKeyManager
    extends KeyManagerBase<Aead, KmsEnvelopeAeadKey, KmsEnvelopeAeadKeyFormat> {
  public KmsEnvelopeAeadKeyManager() {
    super(Aead.class, KmsEnvelopeAeadKey.class, KmsEnvelopeAeadKeyFormat.class, TYPE_URL);
  }

  private static final int VERSION = 0;

  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

  @Override
  public Aead getPrimitiveFromKey(KmsEnvelopeAeadKey keyProto) throws GeneralSecurityException {
    String keyUri = keyProto.getParams().getKekUri();
    KmsClient kmsClient = KmsClients.get(keyUri);
    Aead remote = kmsClient.getAead(keyUri);
    return new KmsEnvelopeAead(keyProto.getParams().getDekTemplate(), remote);
  }

  @Override
  public KmsEnvelopeAeadKey newKeyFromFormat(KmsEnvelopeAeadKeyFormat format)
      throws GeneralSecurityException {
    return KmsEnvelopeAeadKey.newBuilder().setParams(format).setVersion(VERSION).build();
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
  protected KmsEnvelopeAeadKey parseKeyProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return KmsEnvelopeAeadKey.parseFrom(byteString);
  }

  @Override
  protected KmsEnvelopeAeadKeyFormat parseKeyFormatProto(ByteString byteString)
      throws InvalidProtocolBufferException {
    return KmsEnvelopeAeadKeyFormat.parseFrom(byteString);
  }

  @Override
  protected void validateKey(KmsEnvelopeAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
  }

  @Override
  protected void validateKeyFormat(KmsEnvelopeAeadKeyFormat format)
      throws GeneralSecurityException {}
}
