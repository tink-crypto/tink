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

import com.google.crypto.tink.subtle.Enums.HashType;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.regex.Pattern;

/**
 * Validation helper methods.
 *
 * @since 1.0.0
 */
public final class Validators {
  private static final String TYPE_URL_PREFIX = "type.googleapis.com/";
  /**
   * To reach 128-bit security strength, RSA's modulus must be at least 3072-bit while 2048-bit RSA
   * key only has 112-bit security. Nevertheless, a 2048-bit RSA key is considered safe by NIST
   * until 2030 (see https://www.keylength.com/en/4/).
   */
  private static final int MIN_RSA_MODULUS_SIZE = 2048;
  /** @throws GeneralSecurityException if {@code typeUrl} is in invalid format. */
  public static void validateTypeUrl(String typeUrl) throws GeneralSecurityException {
    if (!typeUrl.startsWith(TYPE_URL_PREFIX)) {
      throw new GeneralSecurityException(
          String.format(
              "Error: type URL %s is invalid; it must start with %s.\n", typeUrl, TYPE_URL_PREFIX));
    }
    if (typeUrl.length() == TYPE_URL_PREFIX.length()) {
      throw new GeneralSecurityException(
          String.format("Error: type URL %s is invalid; it has no message name.\n", typeUrl));
    }
  }

  /** @throws InvalidAlgorithmParameterException if {@code sizeInBytes} is not supported. */
  public static void validateAesKeySize(int sizeInBytes) throws InvalidAlgorithmParameterException {
    if (sizeInBytes != 16 && sizeInBytes != 32) {
      throw new InvalidAlgorithmParameterException(
          String.format(
              "invalid key size %d; only 128-bit and 256-bit AES keys are supported",
              sizeInBytes * 8));
    }
  }

  /**
   * @throws GeneralSecurityException if {@code candidate} is negative or larger than {@code
   *     maxExpected}.
   */
  public static void validateVersion(int candidate, int maxExpected)
      throws GeneralSecurityException {
    if (candidate < 0 || candidate > maxExpected) {
      throw new GeneralSecurityException(
          String.format(
              "key has version %d; only keys with version in range [0..%d] are supported",
              candidate, maxExpected));
    }
  }

  /**
   * Validates whether {@code hash} is safe to use for digital signature.
   *
   * @throws GeneralSecurityException if {@code hash} is invalid or is not safe to use for digital
   *     signature.
   */
  public static void validateSignatureHash(HashType hash) throws GeneralSecurityException {
    switch (hash) {
      case SHA256: // fall through
      case SHA384: // fall through
      case SHA512:
        return;
      default:
        break;
    }
    throw new GeneralSecurityException("Unsupported hash: " + hash.name());
  }

  /**
   * Validates whether {@code modulusSize} is at least 2048-bit.
   *
   * <p>To reach 128-bit security strength, RSA's modulus must be at least 3072-bit while 2048-bit
   * RSA key only has 112-bit security. Nevertheless, a 2048-bit RSA key is considered safe by NIST
   * until 2030 (see https://www.keylength.com/en/4/).
   *
   * @throws GeneralSecurityException if {@code modulusSize} is less than 2048-bit.
   */
  public static void validateRsaModulusSize(int modulusSize) throws GeneralSecurityException {
    if (modulusSize < MIN_RSA_MODULUS_SIZE) {
      throw new GeneralSecurityException(
          String.format(
              "Modulus size is %d; only modulus size >= 2048-bit is supported", modulusSize));
    }
  }

  /*
   * @throws IOException if {@code f} exists.
   */
  public static void validateNotExists(File f) throws IOException {
    if (f.exists()) {
      throw new IOException(String.format("%s exists, please choose another file\n", f.toString()));
    }
  }

  /** @throws IOException if {@code f} does not exists. */
  public static void validateExists(File f) throws IOException {
    if (!f.exists()) {
      throw new IOException(
          String.format("Error: %s doesn't exist, please choose another file\n", f.toString()));
    }
  }

  /**
   * Validates that {@code kmsKeyUri} starts with {@code expectedPrefix}, and removes the prefix.
   *
   * @throws IllegalArgumentException
   */
  public static String validateKmsKeyUriAndRemovePrefix(String expectedPrefix, String kmsKeyUri)
      throws IllegalArgumentException {
    if (!kmsKeyUri.toLowerCase().startsWith(expectedPrefix)) {
      throw new IllegalArgumentException(
          String.format("key URI must start with %s", expectedPrefix));
    }
    return kmsKeyUri.substring(expectedPrefix.length());
  }

  // See https://tools.ietf.org/html/rfc3986#section-2.3.
  private static final String URI_UNRESERVED_CHARS = "([0-9a-zA-Z\\-\\.\\_~])+";

  private static final Pattern GCP_KMS_CRYPTO_KEY_PATTERN =
      Pattern.compile(
          String.format(
              "^projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s$",
              URI_UNRESERVED_CHARS,
              URI_UNRESERVED_CHARS,
              URI_UNRESERVED_CHARS,
              URI_UNRESERVED_CHARS),
          Pattern.CASE_INSENSITIVE);

  private static final Pattern GCP_KMS_CRYPTO_KEY_VERSION_PATTERN =
      Pattern.compile(
          String.format(
              "^projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s$",
              URI_UNRESERVED_CHARS,
              URI_UNRESERVED_CHARS,
              URI_UNRESERVED_CHARS,
              URI_UNRESERVED_CHARS,
              URI_UNRESERVED_CHARS),
          Pattern.CASE_INSENSITIVE);
  /**
   * @throws GeneralSecurityException if {@code kmsKeyUri} is not a valid URI of a CryptoKey in
   *     Google Cloud KMS.
   */
  public static void validateCryptoKeyUri(String kmsKeyUri) throws GeneralSecurityException {
    if (!GCP_KMS_CRYPTO_KEY_PATTERN.matcher(kmsKeyUri).matches()) {
      if (GCP_KMS_CRYPTO_KEY_VERSION_PATTERN.matcher(kmsKeyUri).matches()) {
        throw new GeneralSecurityException(
            "Invalid Google Cloud KMS Key URI. "
                + "The URI must point to a CryptoKey, not a CryptoKeyVersion");
      }
      throw new GeneralSecurityException(
          "Invalid Google Cloud KMS Key URI. "
              + "The URI must point to a CryptoKey in the format "
              + "projects/*/locations/*/keyRings/*/cryptoKeys/*. "
              + "See https://cloud.google.com/kms/docs/reference/rest/v1"
              + "/projects.locations.keyRings.cryptoKeys#CryptoKey");
    }
  }
}
