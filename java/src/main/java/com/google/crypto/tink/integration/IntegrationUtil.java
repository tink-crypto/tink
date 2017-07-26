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

import java.util.regex.Pattern;
import java.security.GeneralSecurityException;

/**
 * Integration helper methods.
 */
public final class IntegrationUtil {
  /**
   * Validates that {@code kmsKeyUri} starts with {@code expectedPrefix},
   * and removes the prefix.
   * @throws GeneralSecurityException
   */
  public static String validateAndRemovePrefix(String expectedPrefix, String kmsKeyUri)
      throws GeneralSecurityException {
    if (!kmsKeyUri.toLowerCase().startsWith(expectedPrefix)) {
      throw new GeneralSecurityException(String.format(
          "key URI must start with %s", expectedPrefix));
    }
    return kmsKeyUri.substring(expectedPrefix.length());
  }

  // See https://tools.ietf.org/html/rfc3986#section-2.3.
  private static final String URI_UNRESERVED_CHARS = "([0-9a-zA-Z\\-\\.\\_~])+";

  private static final Pattern GCP_KMS_CRYPTO_KEY_PATTERN = Pattern.compile(
        String.format("^projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s$",
            URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS, URI_UNRESERVED_CHARS,
            URI_UNRESERVED_CHARS),
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

}
