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
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.regex.Pattern;

/**
 * Helper methods for envelope encryption.
 */
public final class GcpKmsClient {
  private static final String APPLICATION_NAME = "Tink";

  // See https://tools.ietf.org/html/rfc3986#section-2.3.
  private static final String URI_UNRESERVED_CHARS = "([0-9a-zA-Z\\-\\.\\_~])+";

  private static final Pattern GCP_KMS_CRYPTO_KEY_PATTERN = Pattern.compile(
        String.format("^projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s$",
            URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS),
        Pattern.CASE_INSENSITIVE);

  private static final Pattern GCP_KMS_CRYPTO_KEY_VERSION_PATTERN = Pattern.compile(
        String.format("^projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s$",
            URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS,
            URI_UNRESERVED_CHARS),
        Pattern.CASE_INSENSITIVE);
  /**
   * @throws GeneralSecurityException if {@code kmsKeyUri} is not a valid URI of a CryptoKey
   * in Google Cloud KMS.
   */
  public static void validateCryptoKeyUri(String kmsKeyUri)
      throws GeneralSecurityException {
    if (!GCP_KMS_CRYPTO_KEY_PATTERN.matcher(kmsKeyUri).matches()) {
      if (GCP_KMS_CRYPTO_KEY_VERSION_PATTERN.matcher(kmsKeyUri).matches()) {
        throw new GeneralSecurityException("Invalid Google Cloud KMS Key URI. "
          + "The URI must point to a CryptoKey, not a CryptoKeyVersion");
      }
      throw new GeneralSecurityException("Invalid Google Cloud KMS Key URI. "
          + "The URI must point to a CryptoKey in the format "
          + "projects/*/locations/*/keyRings/*/cryptoKeys/*. "
          + "See https://cloud.google.com/kms/docs/reference/rest/v1"
          + "/projects.locations.keyRings.cryptoKeys#CryptoKey");
    }
  }

  /**
   * Initializes a cloud kms client based on default credential (provided by GCE/GCloud CLI).
   *
   * @throws IOException if the client initialization fails.
   */
  public static CloudKMS fromDefaultCredential() throws IOException {
    GoogleCredential credential =
        GoogleCredential.getApplicationDefault(
            new NetHttpTransport(), new JacksonFactory());
    return fromProvidedCredential(credential);
  }

  /**
   * Initializes a cloud kms client based on a credential from a service
   * account JSON file that can be downloaded from Google Cloud Console.
   *
   * @throws IOException if the client initialization fails.
   */
  public static CloudKMS fromServiceAccount(File serviceAccount)
      throws IOException {
    GoogleCredential credential = GoogleCredential.fromStream(
        new ByteArrayInputStream(Files.readAllBytes(serviceAccount.toPath())));
    return fromProvidedCredential(credential);
  }

  /**
   * Initializes a cloud kms client based on a credential from a nullable
   * service account. If the service account is null, use the default credential
   * (provided by GCE/GCloud CLI)
   * @throws IOException if the client initialization fails.
   */
  public static CloudKMS fromNullableServiceAccount(File serviceAccount)
      throws IOException {
    if (serviceAccount == null) {
      return fromDefaultCredential();
    }
    return fromServiceAccount(serviceAccount);
  }

  /**
   * Initializes a cloud kms client based on a provided credential.
   *
   * @throws IOException if the client initialization fails.
   */
  public static CloudKMS fromProvidedCredential(GoogleCredential credential)
      throws IOException {
    if (credential.createScopedRequired()) {
      credential = credential.createScoped(CloudKMSScopes.all());
    }
    return new CloudKMS.Builder(new NetHttpTransport(), new JacksonFactory(), credential)
            .setApplicationName(APPLICATION_NAME)
            .build();
  }
}
