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
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.Util;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

class KmsEnvelopeAeadKeyManager implements KeyManager<Aead> {
  private static final int VERSION = 0;

  private static final String KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.KmsEnvelopeAeadKey";

  @Override
  public Aead getPrimitive(Any proto) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKey key = KmsEnvelopeAeadKey.parseFrom(proto.getValue());
      validate(key);
      Aead remote = Registry.INSTANCE.getPrimitive(key.getParams().getKmsKey());
      return new KmsEnvelopeAead(key.getParams().getDekFormat(), remote);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid KMSEnvelopeAead key");
    }
  }

  @Override
  public Any newKey(KeyFormat keyFormat) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.parseFrom(
          keyFormat.getFormat().getValue());
      // special key type, doesn't actually store any key material.
      return Util.pack(KEY_TYPE, KmsEnvelopeAeadKey.newBuilder()
          .setParams(format.getParams())
          .setVersion(VERSION)
          .build());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(e);
    }
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(KEY_TYPE);
  }

  private void validate(KmsEnvelopeAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
