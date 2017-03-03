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

package com.example.envelopeme;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.services.cloudkms.v1beta1.CloudKMSScopes;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.aead.GoogleCredentialFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Produces {@code GoogleCredential} used in tests.
 */
public class EnvelopeMeGoogleCredentialFactory implements GoogleCredentialFactory {

  private final byte[] serviceAccount;

  public EnvelopeMeGoogleCredentialFactory(final byte[] serviceAccount) {
    this.serviceAccount = serviceAccount;
  }
  /**
   * Depending on {@code key}, produces either a default credential or a hardcoded one.
   */
  @Override
  public GoogleCredential getCredential(GoogleCloudKmsAeadKey key) throws IOException {
    GoogleCredential cred = createGoogleCredential(this.serviceAccount);
    // Depending on the environment that provides the default credentials (e.g. Compute Engine, App
    // Engine), the credentials may require us to specify the scopes we need explicitly.
    // Check for this case, and inject the scope if required.
    if (cred.createScopedRequired()) {
      cred = cred.createScoped(CloudKMSScopes.all());
    }
    return cred;
  }

  /**
   * @returns a {@code GoogleCredential} from a {@code serviceAccount}.
   */
  public static GoogleCredential createGoogleCredential(byte[] serviceAccount) throws IOException {
    return GoogleCredential.fromStream(
        new ByteArrayInputStream(serviceAccount));
  }
}