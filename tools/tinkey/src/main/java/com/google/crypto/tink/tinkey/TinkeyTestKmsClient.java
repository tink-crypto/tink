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
package com.google.crypto.tink.tinkey;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.auto.service.AutoService;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * A client for testing.
 *
 * <p>The client supports all key uris which start with "tinkey-test-kms-client://" followed by a
 * JSON-encoded AEAD keyset. It will use this Aead when "getAead" is called. As credentials, it must
 * be given a file which starts whose contents are "VALID CREDENTIALS".
 */
@AutoService(KmsClient.class)
public final class TinkeyTestKmsClient implements KmsClient {

  public TinkeyTestKmsClient() {}

  private static final String PREFIX = "tinkey-test-kms-client://";
  private static final String CREDENTIALS_FILE_CONTENTS = "VALID CREDENTIALS";

  static String createKeyUri(KeysetHandle handle) throws GeneralSecurityException {
    return PREFIX
        + TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
  }

  static void createCredentialFile(Path path) throws IOException {
    Files.write(path, CREDENTIALS_FILE_CONTENTS.getBytes(UTF_8));
  }

  private static String stripPrefix(String str) throws GeneralSecurityException {
    if (!str.startsWith(PREFIX)) {
      throw new GeneralSecurityException("Invalid key uri: " + str);
    }
    return str.substring(PREFIX.length());
  }

  @Override
  public boolean doesSupport(String keyUri) {
    return keyUri.startsWith(PREFIX);
  }

  byte[] credentialFileContents = new byte[] {};

  @Override
  public KmsClient withCredentials(String credentials) throws GeneralSecurityException {
    try {
      credentialFileContents = Files.readAllBytes(Paths.get(credentials));
      return this;
    } catch (IOException e) {
      throw new GeneralSecurityException(e);
    }
  }

  @Override
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    throw new GeneralSecurityException("TinkeyTestKmsClient has no default credentials");
  }

  private void checkCredentials() throws GeneralSecurityException {
    if (!Arrays.equals(credentialFileContents, CREDENTIALS_FILE_CONTENTS.getBytes(UTF_8))) {
      throw new GeneralSecurityException(
          "Invalid credentials: " + Arrays.toString(credentialFileContents));
    }
  }

  @Override
  public Aead getAead(String keyUri) throws GeneralSecurityException {
    checkCredentials();
    String keyset = stripPrefix(keyUri);
    return TinkJsonProtoKeysetFormat.parseKeyset(keyset, InsecureSecretKeyAccess.get())
        .getPrimitive(Aead.class);
  }
}
