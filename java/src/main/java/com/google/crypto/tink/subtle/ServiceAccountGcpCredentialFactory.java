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

package com.google.crypto.tink.subtle;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.common.base.Optional;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * A {@code GcpCredentialFactory} that returns a {@code GoogleCredential} from an optional
 * service account JSON file, which can be downloaded from Google Cloud Console. If the
 * service account JSON file is absent, this factory returns a {@code GoogleCredential} using
 * Application Default Credentials, @see
 * https://g.co/dv/identity/protocols/application-default-credentials.
 */
public class ServiceAccountGcpCredentialFactory implements GcpCredentialFactory {
  private final Optional<File> serviceAccount;

  public ServiceAccountGcpCredentialFactory(Optional<File> serviceAccount) {
    this.serviceAccount = serviceAccount;
  }

  @Override
  public GoogleCredential createCredential(String kmsKeyUri /* unused */) throws IOException {
    GoogleCredential cred;
    if (serviceAccount.isPresent()) {
      cred = createServiceAccountGoogleCredential(serviceAccount.get());
    } else {
      cred = GoogleCredential.getApplicationDefault();
    }
    cred = cred.createScoped(GcpScopes.all());
    return cred;
  }

  /**
   * @return {@code GoogleCredential} from {@code serviceAccount}.
   */
  public static GoogleCredential createServiceAccountGoogleCredential(File serviceAccount)
      throws IOException {
    return GoogleCredential.fromStream(
        new ByteArrayInputStream(Files.readAllBytes(serviceAccount.toPath())));
  }
}
