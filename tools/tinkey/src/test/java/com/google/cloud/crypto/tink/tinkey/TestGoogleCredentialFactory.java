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

package com.google.cloud.crypto.tink.tinkey;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;
import com.google.cloud.crypto.tink.GoogleCloudKmsProto.GoogleCloudKmsAeadKey;
import com.google.cloud.crypto.tink.aead.GoogleCredentialFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Produces {@code GoogleCredential} used in tests.
 */
public class TestGoogleCredentialFactory implements GoogleCredentialFactory {
  // This GCP KMS CryptoKey is restricted to the service account created by
  // {@code createGoogleCredential}.
  public static final String RESTRICTED_CRYPTO_KEY_URI = String.format(
        "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
        "testing-cloud-kms-159306", "global", "tink_unit_tests", "restricted");

  // This is a credential of a service account that is granted access to
  // {@code RESTRICTED_CRYPTO_KEY_URI}.
  public static final File CREDENTIAL_FILE = Paths.get(
      "testdata/credential.json")
      .toFile();


  /**
   * Depending on {@code key}, produces either a default credential or a hardcoded one.
   */
  @Override
  public GoogleCredential getCredential(GoogleCloudKmsAeadKey key) throws IOException {
    GoogleCredential cred;
    if (key.getKmsKeyUri().equals(RESTRICTED_CRYPTO_KEY_URI)) {
      cred = createGoogleCredential();
    } else {
      cred = GoogleCredential.getApplicationDefault();
    }
    cred = cred.createScoped(CloudKMSScopes.all());
    return cred;
  }

  /**
   * @return {@code GoogleCredential} that is granted access to
   * {@code RESTRICTED_CRYPTO_KEY_URI}.
   */
  public static GoogleCredential createGoogleCredential() throws IOException {
    return GoogleCredential.fromStream(
        new ByteArrayInputStream(Files.readAllBytes(CREDENTIAL_FILE.toPath())));
  }
}
