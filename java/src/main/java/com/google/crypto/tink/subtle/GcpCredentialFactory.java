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
import java.io.IOException;

/**
 * This interface produces {@code GoogleCredential} that can be used to authorize
 * calls to Google Cloud.
 */
public interface GcpCredentialFactory {
  /**
   * Produces {@code GoogleCredential} for the Google Cloud KMS key at {@code kmsKeyUri}.
   */
  public GoogleCredential createCredential(String kmsKeyUri) throws IOException;
}
