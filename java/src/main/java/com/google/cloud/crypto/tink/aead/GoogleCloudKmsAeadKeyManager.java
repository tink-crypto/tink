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

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKeyFormat;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.subtle.GoogleCloudKmsAead;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of GoogleCloudKmsAead.
 * Currently it doesn't support key generation. To use it one must
 * provide an implementation of {@code GoogleCredentialFactory}.
 */
public class GoogleCloudKmsAeadKeyManager
    implements KeyManager<Aead, GoogleCloudKmsAeadKey, GoogleCloudKmsAeadKeyFormat> {
  private static final int VERSION = 0;

  private static final String KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.GoogleCloudKmsAeadKey";

  private final GoogleCredentialFactory credFactory;

  public GoogleCloudKmsAeadKeyManager(GoogleCredentialFactory credFactory) {
    this.credFactory = credFactory;
  }

  @Override
  public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
    try {
      GoogleCloudKmsAeadKey keyProto = GoogleCloudKmsAeadKey.parseFrom(serialized);
      return getPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid GoogleCloudKmsAead key");
    }
  }

  @Override
  public Aead getPrimitive(GoogleCloudKmsAeadKey keyProto) throws GeneralSecurityException {
    try {
      validate(keyProto);
      return new GoogleCloudKmsAead(createCloudKmsClient(keyProto), keyProto.getKmsKeyUri());
    } catch (IOException e) {
      throw new GeneralSecurityException("invalid GoogleCloudKmsAead key");
    }
  }

  @Override
  public GoogleCloudKmsAeadKey newKey(ByteString serialized) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented");
  }

  @Override
  public GoogleCloudKmsAeadKey newKey(GoogleCloudKmsAeadKeyFormat format)
      throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented");
  }

  @Override
  public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
    throw new GeneralSecurityException("Not Implemented");
  }

  @Override
  public boolean doesSupport(String typeUrl) {
    return typeUrl.equals(KEY_TYPE);
  }

  private CloudKMS createCloudKmsClient(GoogleCloudKmsAeadKey key) throws IOException {
    HttpTransport transport = new NetHttpTransport();
    JsonFactory jsonFactory = new JacksonFactory();
    GoogleCredential cred = this.credFactory.getCredential(key);
    return new CloudKMS.Builder(transport, jsonFactory, cred)
        .setApplicationName("Tink")
        .build();
  }

  private void validate(GoogleCloudKmsAeadKey key) throws GeneralSecurityException {
    SubtleUtil.validateVersion(key.getVersion(), VERSION);
  }
}
