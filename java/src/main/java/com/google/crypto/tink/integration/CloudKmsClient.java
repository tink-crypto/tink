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

package com.google.crypto.tink.integration;

import com.google.crypto.tink.subtle.KmsClient;
import com.amazonaws.services.kms.AWSKMS;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.crypto.tink.Aead;
import java.security.GeneralSecurityException;

/**
 * A {@code KmsClient} that can produce primitives backed by keys stored in GCP KMS or
 * AWS KMS.
 */
public final class CloudKmsClient implements KmsClient {
  private static final String GCP_KMS_PREFIX = "gcp-kms://";
  private static final String AWS_KMS_PREFIX = "aws-kms://";

  private AWSKMS awsKmsClient;
  private CloudKMS gcpKmsClient;

  public CloudKmsClient() {}

  public CloudKmsClient withAwsKmsClient(AWSKMS client) {
    this.awsKmsClient = client;
    return this;
  }

  public CloudKmsClient withGcpKmsClient(CloudKMS client) {
    this.gcpKmsClient = client;
    return this;
  }

  @Override
  public Aead getAead(String keyUri) throws GeneralSecurityException {
    if (keyUri.toLowerCase().startsWith(GCP_KMS_PREFIX)) {
      return new GcpKmsAead(gcpKmsClient, keyUri);
    } else if (keyUri.toLowerCase().startsWith(AWS_KMS_PREFIX)) {
      return new AwsKmsAead(awsKmsClient, keyUri);
    }
    throw new GeneralSecurityException(
        String.format("key URI must start with either %s or %s",
            GCP_KMS_PREFIX, AWS_KMS_PREFIX));
  }
}
