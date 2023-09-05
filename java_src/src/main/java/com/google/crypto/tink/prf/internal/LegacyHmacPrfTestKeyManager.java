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

package com.google.crypto.tink.prf.internal;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacPrfKey;
import com.google.crypto.tink.proto.HmacPrfParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Test helper key manager emulating a user that has a custom old KeyManager implementation with a
 * custom Prf primitive. In order to test our code handling such cases.
 */
public class LegacyHmacPrfTestKeyManager implements KeyManager<Prf> {
  /** Type url that this manager does support. */
  public static final String TYPE_URL = "type.googleapis.com/google.crypto.tink.HmacPrfKey";

  /** Current version of this key manager. Keys with version equal or smaller are supported. */
  private static final int VERSION = 0;

  /** Minimum key size in bytes. */
  private static final int MIN_KEY_SIZE_IN_BYTES = 16;

  /**
   * @param serializedKey serialized {@code HmacPrfKey} proto
   */
  @Override
  public Prf getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      HmacPrfKey keyProto =
          HmacPrfKey.parseFrom(serializedKey, ExtensionRegistryLite.getEmptyRegistry());
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected serialized HmacPrfKey proto", e);
    }
  }

  /**
   * @param key {@code HmacPrfKey} proto
   */
  @Override
  public Prf getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof HmacPrfKey)) {
      throw new GeneralSecurityException("Expected HmacPrfKey proto");
    }
    HmacPrfKey keyProto = (HmacPrfKey) key;
    validate(keyProto);
    HashType hash = keyProto.getParams().getHash();
    byte[] keyValue = keyProto.getKeyValue().toByteArray();
    SecretKeySpec keySpec = new SecretKeySpec(keyValue, "HMAC");
    switch (hash) {
      case SHA1:
        return new PrfHmacJce("HMACSHA1", keySpec);
      case SHA224:
        return new PrfHmacJce("HMACSHA224", keySpec);
      case SHA256:
        return new PrfHmacJce("HMACSHA256", keySpec);
      case SHA384:
        return new PrfHmacJce("HMACSHA384", keySpec);
      case SHA512:
        return new PrfHmacJce("HMACSHA512", keySpec);
      default:
        throw new GeneralSecurityException("unknown hash");
    }
  }

  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }

  @Override
  public MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(TYPE_URL);
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public int getVersion() {
    return VERSION;
  }

  @Override
  public Class<Prf> getPrimitiveClass() {
    return Prf.class;
  }

  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new UnsupportedOperationException("not needed for tests");
  }

  private void validate(HmacPrfKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), VERSION);
    if (key.getKeyValue().size() < MIN_KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("key too short");
    }
    validate(key.getParams());
  }

  private void validate(HmacPrfParams params) throws GeneralSecurityException {
    switch (params.getHash()) {
      case SHA1:
      case SHA224:
      case SHA256:
      case SHA384:
      case SHA512:
        return;
      default:
        throw new GeneralSecurityException("unknown hash type");
    }
  }

  static void register() throws GeneralSecurityException {
    Registry.registerKeyManager(new LegacyHmacPrfTestKeyManager(), true);
  }
}
