// Copyright 2023 Google LLC
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

package com.google.crypto.tink.aead.internal;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesCtrJceCipher;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * Test helper key manager emulating a user that has a custom old KeyManager implementation with a
 * custom StreamingAead primitive. In order to test our code handling such cases.
 */
public class LegacyAesCtrHmacTestKeyManager implements KeyManager<Aead> {

  private static final String TYPE_URL = "type.googleapis.com/custom.AesCtrHmacAeadKey";
  private static final int MIN_AES_CTR_IV_SIZE_IN_BYTES = 12;

  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    AesCtrHmacAeadKey keyProto;
    try {
      keyProto =
          AesCtrHmacAeadKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("failed to parse the key", e);
    }
    return new EncryptThenAuthenticate(
        new AesCtrJceCipher(
            keyProto.getAesCtrKey().getKeyValue().toByteArray(),
            keyProto.getAesCtrKey().getParams().getIvSize()),
        new HmacKeyManager().getPrimitive(keyProto.getHmacKey(), Mac.class),
        keyProto.getHmacKey().getParams().getTagSize());
  }

  public void validateKey(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    // Validate overall.
    Validators.validateVersion(key.getVersion(), getVersion());

    // Validate AesCtrKey.
    AesCtrKey aesCtrKey = key.getAesCtrKey();
    Validators.validateVersion(aesCtrKey.getVersion(), /* maxExpected= */ 0);
    Validators.validateAesKeySize(aesCtrKey.getKeyValue().size());
    AesCtrParams aesCtrParams = aesCtrKey.getParams();
    if (aesCtrParams.getIvSize() < MIN_AES_CTR_IV_SIZE_IN_BYTES || aesCtrParams.getIvSize() > 16) {
      throw new GeneralSecurityException("invalid AES STR IV size");
    }

    // Validate HmacKey.
    new HmacKeyManager().validateKey(key.getHmacKey());
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<Aead> getPrimitiveClass() {
    return Aead.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }

  public static void register() throws GeneralSecurityException {
    Registry.registerKeyManager(new LegacyAesCtrHmacTestKeyManager(), true);
  }
}
