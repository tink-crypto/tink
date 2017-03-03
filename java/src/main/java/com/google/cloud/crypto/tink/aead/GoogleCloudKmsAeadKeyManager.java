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
import com.google.api.services.cloudkms.v1beta1.CloudKMS;
import com.google.cloud.crypto.tink.Aead;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.subtle.GoogleCloudKmsAead;
import com.google.cloud.crypto.tink.subtle.Util;
import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * This key manager produces new instances of GoogleCloudKmsAead.
 * Currently it doesn't support key generation. To use it one must
 * provide an implementation of {@code GoogleCredentialFactory}.
 */
class GoogleCloudKmsAeadKeyManager implements KeyManager<Aead> {
  private static final int VERSION = 0;

  private static final String KEY_TYPE =
      "type.googleapis.com/google.cloud.crypto.tink.GoogleCloudKmsAeadKey";

  private final GoogleCredentialFactory credFactory;

  public GoogleCloudKmsAeadKeyManager(GoogleCredentialFactory credFactory) {
    this.credFactory = credFactory;
  }

  @Override
  public Aead getPrimitive(Any proto) throws GeneralSecurityException {
    try {
      GoogleCloudKmsAeadKey key = proto.unpack(GoogleCloudKmsAeadKey.class);
      validate(key);
      return new GoogleCloudKmsAead(createCloudKmsClient(key), key.getKmsKeyUri());
    } catch (IOException e) {
      throw new GeneralSecurityException(e);
    }
  }

  @Override
  public Any newKey(KeyFormat keyFormat) throws GeneralSecurityException {
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
    Util.validateVersion(key.getVersion(), VERSION);
  }
}
