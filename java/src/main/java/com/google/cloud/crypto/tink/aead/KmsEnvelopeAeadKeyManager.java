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
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.KmsEnvelopeProto.KmsEnvelopeAeadKey;
import com.google.cloud.crypto.tink.KmsEnvelopeProto.KmsEnvelopeAeadKeyFormat;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

class KmsEnvelopeAeadKeyManager
    implements KeyManager<Aead, KmsEnvelopeAeadKey, KmsEnvelopeAeadKeyFormat> {
  private static final int VERSION = 0;

  private static final String KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.KmsEnvelopeAeadKey";

  @Override
  public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKey keyProto = KmsEnvelopeAeadKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid KMSEnvelopeAead key");
    }
  }

  @Override
  public Aead getPrimitive(KmsEnvelopeAeadKey keyProto) throws GeneralSecurityException {
    validate(keyProto);
    Aead remote = Registry.INSTANCE.getPrimitive(keyProto.getParams().getKmsKey());
    return new KmsEnvelopeAead(keyProto.getParams().getDekTemplate(), remote);
  }

  @Override
  public KmsEnvelopeAeadKey newKey(ByteString serialized) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.parseFrom(serialized);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid KmsEnvelopeAead key format", e);
    }
  }

  @Override
  public KmsEnvelopeAeadKey newKey(KmsEnvelopeAeadKeyFormat format)
      throws GeneralSecurityException {
    return KmsEnvelopeAeadKey.newBuilder()
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    KmsEnvelopeAeadKey key = newKey(serialized);
    return KeyData.newBuilder()
        .setTypeUrl(KEY_TYPE)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.REMOTE)
        .build();
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(KEY_TYPE);
  }

  private void validate(KmsEnvelopeAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
