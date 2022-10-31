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

package com.google.crypto.tink.integration.gcpkms;

import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import com.google.crypto.tink.Aead;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A {@link Aead} that forwards encryption/decryption requests to a key in <a
 * href="https://cloud.google.com/kms/">Google Cloud KMS</a>.
 *
 * <p>As of August 2017, Google Cloud KMS supports only AES-256-GCM keys.
 *
 * @since 1.0.0
 */
public final class GcpKmsAead implements Aead {

  /** This client knows how to talk to Google Cloud KMS. */
  private final CloudKMS kmsClient;

  // The location of a CryptoKey in Google Cloud KMS.
  // Valid values have this format: projects/*/locations/*/keyRings/*/cryptoKeys/*.
  // See https://cloud.google.com/kms/docs/object-hierarchy.
  private final String kmsKeyUri;

  public GcpKmsAead(CloudKMS kmsClient, String keyUri) throws GeneralSecurityException {
    this.kmsClient = kmsClient;
    this.kmsKeyUri = keyUri;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] aad) throws GeneralSecurityException {
    try {
      EncryptRequest request =
          new EncryptRequest().encodePlaintext(plaintext).encodeAdditionalAuthenticatedData(aad);
      EncryptResponse response =
          this.kmsClient
              .projects()
              .locations()
              .keyRings()
              .cryptoKeys()
              .encrypt(this.kmsKeyUri, request)
              .execute();
      return toNonNullableByteArray(response.decodeCiphertext());
    } catch (IOException e) {
      throw new GeneralSecurityException("encryption failed", e);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] aad) throws GeneralSecurityException {
    try {
      DecryptRequest request =
          new DecryptRequest().encodeCiphertext(ciphertext).encodeAdditionalAuthenticatedData(aad);
      DecryptResponse response =
          this.kmsClient
              .projects()
              .locations()
              .keyRings()
              .cryptoKeys()
              .decrypt(this.kmsKeyUri, request)
              .execute();
      return toNonNullableByteArray(response.decodePlaintext());
    } catch (IOException e) {
      throw new GeneralSecurityException("decryption failed", e);
    }
  }

  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

  private static byte[] toNonNullableByteArray(byte[] data) {
    if (data == null) {
      return EMPTY_BYTE_ARRAY;
    } else {
      return data;
    }
  }
}
