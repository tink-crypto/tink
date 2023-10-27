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
package com.google.crypto.tink.integration.gcpkms;

import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.stub.GrpcKeyManagementServiceStub;
import com.google.cloud.kms.v1.stub.KeyManagementServiceStubSettings;
import java.security.GeneralSecurityException;

/** A partial, fake implementation of {@link com.google.cloud.kms.v1.KeyManagementServiceClient}. */
final class FakeKeyManagementServiceClient {
  public FakeKeyManagementServiceClient() {}

  public static KeyManagementServiceClient createKeyManagementServiceClient()
      throws GeneralSecurityException {
    try {
      KeyManagementServiceStubSettings.Builder kmsSettingsBuilder =
          KeyManagementServiceStubSettings.newBuilder();
      KeyManagementServiceStubSettings kmsSettings = kmsSettingsBuilder.build();
      GrpcKeyManagementServiceStub grpcKmsStub = GrpcKeyManagementServiceStub.create(kmsSettings);
      return KeyManagementServiceClient.create(grpcKmsStub);
    } catch (Exception e) {
      throw new GeneralSecurityException("creation of FakeKeyManagementServiceClient failed", e);
    }
  }
}
