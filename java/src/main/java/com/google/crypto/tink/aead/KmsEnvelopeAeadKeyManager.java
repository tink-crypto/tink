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
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code KmsEnvelopeAeadKey} keys and produces new instances
 * of {@code KmsEnvelopeAead}.
 */
public final class KmsEnvelopeAeadKeyManager implements KeyManager<Aead> {
  KmsEnvelopeAeadKeyManager() {}

  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

  /**
   * @param serializedKey  serialized {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKey keyProto = KmsEnvelopeAeadKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmSEnvelopeAeadKey proto", e);
    }
  }

  /**
   * @param key  {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof KmsEnvelopeAeadKey)) {
      throw new GeneralSecurityException("expected KmsEnvelopeAeadKey proto");
    }
    KmsEnvelopeAeadKey keyProto = (KmsEnvelopeAeadKey) key;
    validate(keyProto);
    Aead remote = Registry.INSTANCE.getPrimitive(keyProto.getParams().getKmsKey());
    return new KmsEnvelopeAead(keyProto.getParams().getDekTemplate(), remote);
  }

  /**
   * @param serializedKeyFormat  serialized {@code KmsEnvelopeAeadKeyFormat} proto
   * @return new {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.parseFrom(serializedKeyFormat);
      return newKey(format);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized KmsEnvelopeAeadKeyFormat proto", e);
    }
  }

  /**
   * @param keyFormat  {@code KmsEnvelopeAeadKeyFormat} proto
   * @return new {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat)
      throws GeneralSecurityException {
    if (!(keyFormat instanceof KmsEnvelopeAeadKeyFormat)) {
      throw new GeneralSecurityException("expected KmsEnvelopeAeadKeyFormat proto");
    }
    KmsEnvelopeAeadKeyFormat format = (KmsEnvelopeAeadKeyFormat) keyFormat;
    return KmsEnvelopeAeadKey.newBuilder()
        .setParams(format.getParams())
        .setVersion(VERSION)
        .build();
  }

  /**
   * @param serializedKeyFormat  serialized {@code KmsEnvelopeAeadKeyFormat} proto
   * @return {@code KeyData} with a new {@code KmsEnvelopeAeadKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    KmsEnvelopeAeadKey key = (KmsEnvelopeAeadKey) newKey(serializedKeyFormat);
    return KeyData.newBuilder()
        .setTypeUrl(TYPE_URL)
        .setValue(key.toByteString())
        .setKeyMaterialType(KeyData.KeyMaterialType.REMOTE)
        .build();
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(TYPE_URL);
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  private void validate(KmsEnvelopeAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
