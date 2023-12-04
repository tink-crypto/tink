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

package com.google.crypto.tink.daead.internal.testing;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * Test helper key manager emulating a user that has a custom old KeyManager implementation with a
 * custom DeterministicAead primitive. Helps testing our code which handles such cases.
 */
public class LegacyAesSivTestKeyManager implements KeyManager<DeterministicAead> {
  /** Custom type url that this manager does support. */
  public static final String TYPE_URL = "type.googleapis.com/custom.AesSivKey";

  private static final int KEY_SIZE_IN_BYTES = 64;

  @Override
  public DeterministicAead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      AesSivKey keyProto =
          AesSivKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      validateKey(keyProto);
      return new AesSiv(keyProto.getKeyValue().toByteArray());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Expected serialized AesSivKey proto", e);
    }
  }

  private void validateKey(AesSivKey key) throws GeneralSecurityException {
    if (key.getKeyValue().size() != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException(
          "Invalid key size: "
              + key.getKeyValue().size()
              + ". Valid keys must have "
              + KEY_SIZE_IN_BYTES
              + " bytes.");
    }
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public Class<DeterministicAead> getPrimitiveClass() {
    return DeterministicAead.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }

  public static void register() throws GeneralSecurityException {
    Registry.registerKeyManager(new LegacyAesSivTestKeyManager(), true);
  }
}
