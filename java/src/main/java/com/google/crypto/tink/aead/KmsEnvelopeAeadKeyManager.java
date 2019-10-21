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
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code KmsEnvelopeAeadKey} keys and produces new instances of
 * {@code KmsEnvelopeAead}.
 */
public class KmsEnvelopeAeadKeyManager extends KeyTypeManager<KmsEnvelopeAeadKey> {
  KmsEnvelopeAeadKeyManager() {
    super(
        KmsEnvelopeAeadKey.class,
        new PrimitiveFactory<Aead, KmsEnvelopeAeadKey>(Aead.class) {
          @Override
          public Aead getPrimitive(KmsEnvelopeAeadKey keyProto) throws GeneralSecurityException {
            String keyUri = keyProto.getParams().getKekUri();
            KmsClient kmsClient = KmsClients.get(keyUri);
            Aead remote = kmsClient.getAead(keyUri);
            return new KmsEnvelopeAead(keyProto.getParams().getDekTemplate(), remote);
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.REMOTE;
  }

  @Override
  public void validateKey(KmsEnvelopeAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
  }

  @Override
  public KmsEnvelopeAeadKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return KmsEnvelopeAeadKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<KmsEnvelopeAeadKeyFormat, KmsEnvelopeAeadKey> keyFactory() {
    return new KeyFactory<KmsEnvelopeAeadKeyFormat, KmsEnvelopeAeadKey>(
        KmsEnvelopeAeadKeyFormat.class) {
      @Override
      public void validateKeyFormat(KmsEnvelopeAeadKeyFormat format)
          throws GeneralSecurityException {}

      @Override
      public KmsEnvelopeAeadKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return KmsEnvelopeAeadKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public KmsEnvelopeAeadKey createKey(KmsEnvelopeAeadKeyFormat format)
          throws GeneralSecurityException {
        return KmsEnvelopeAeadKey.newBuilder().setParams(format).setVersion(getVersion()).build();
      }
    };
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new KmsEnvelopeAeadKeyManager(), newKeyAllowed);
  }
}
