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

import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.proto.GcpKmsAeadKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.GcpKmsAead;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of {@code GcpKmsAead}.
 * Currently it doesn't support key generation. To use it one must
 * provide a KMS client.
 */
public final class GcpKmsAeadKeyManager implements KeyManager<Aead> {
  private static final int VERSION = 0;

  public static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.GcpKmsAeadKey";

  private final CloudKMS cloudKmsClient;

  public GcpKmsAeadKeyManager(CloudKMS cloudKmsClient) {
    this.cloudKmsClient = cloudKmsClient;
  }

  /**
   * @param serializedKey  serialized {@code GcpKmsAeadKey} proto
   */
  @Override
  public Aead getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      GcpKmsAeadKey keyProto = GcpKmsAeadKey.parseFrom(serializedKey);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("expected GcpKmsAeadKey proto", e);
    }
  }

  /**
   * @param key  {@code GcpKmsAeadKey} proto
   */
  @Override
  public Aead getPrimitive(MessageLite key) throws GeneralSecurityException {
    if (!(key instanceof GcpKmsAeadKey)) {
      throw new GeneralSecurityException("expected GcpKmsAeadKey proto");
    }
    GcpKmsAeadKey keyProto = (GcpKmsAeadKey) key;
    validate(keyProto);
    return new GcpKmsAead(cloudKmsClient, keyProto.getKmsKeyUri());
  }

  /**
   * @param serializedKeyFormat  serialized {@code GcpKmsAeadKeyFormat} proto
   * @return new {@code GcpKmsAeadKey} proto
   */
  @Override
  public MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented");
  }

  /**
   * @param keyFormat  {@code GcpKmsAeadKeyFormat} proto
   * @return new {@code GcpKmsAeadKey} proto
   */
  @Override
  public MessageLite newKey(MessageLite keyFormat)
      throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented");
  }

  /**
   * @param serializedKeyFormat  serialized {@code GcpKmsAeadKeyFormat} proto
   * @return {@code KeyData} with a new {@code GcpKmsAeadKey} proto
   */
  @Override
  public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented");
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(TYPE_URL);
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  private static void validate(GcpKmsAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
