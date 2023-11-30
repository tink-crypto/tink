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

import com.google.api.gax.rpc.ApiException;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.crypto.tink.Aead;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * An {@link Aead} that forwards encryption/decryption requests to a key in <a
 * href="https://cloud.google.com/kms/">Google Cloud KMS</a>.
 *
 * <p>As of August 2017, Google Cloud KMS supports only AES-256-GCM keys.
 *
 * @since 1.0.0
 */
public final class GcpKmsAead implements Aead {
  /** An HTTP-based client to communicate with Google Cloud KMS. */
  private final CloudKMS kmsClient;

  // The location of a CryptoKey in Google Cloud KMS.
  // Valid values have this format: projects/*/locations/*/keyRings/*/cryptoKeys/*.
  // See https://cloud.google.com/kms/docs/object-hierarchy.
  private final String keyName;

  public GcpKmsAead(CloudKMS kmsClient, String keyName) {
    this.kmsClient = kmsClient;
    this.keyName = keyName;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      EncryptRequest request =
          new EncryptRequest()
              .encodePlaintext(plaintext)
              .encodeAdditionalAuthenticatedData(associatedData);
      EncryptResponse response =
          this.kmsClient
              .projects()
              .locations()
              .keyRings()
              .cryptoKeys()
              .encrypt(this.keyName, request)
              .execute();
      return toNonNullableByteArray(response.decodeCiphertext());
    } catch (IOException e) {
      throw new GeneralSecurityException("encryption failed", e);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      DecryptRequest request =
          new DecryptRequest()
              .encodeCiphertext(ciphertext)
              .encodeAdditionalAuthenticatedData(associatedData);
      DecryptResponse response =
          this.kmsClient
              .projects()
              .locations()
              .keyRings()
              .cryptoKeys()
              .decrypt(this.keyName, request)
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

  /**
   * An {@link Aead} that forwards encryption/decryption requests to a key in <a
   * href="https://cloud.google.com/kms/">Google Cloud KMS</a> using GRPC.
   */
  private static final class GcpKmsAeadGrpc implements Aead {

    /** A GRPC-based client to communicate with Google Cloud KMS. */
    private final KeyManagementServiceClient kmsClient;

    // The location of a CryptoKey in Google Cloud KMS.
    // Valid values have this format: projects/*/locations/*/keyRings/*/cryptoKeys/*.
    // See https://cloud.google.com/kms/docs/object-hierarchy.
    private final String keyName;

    private GcpKmsAeadGrpc(KeyManagementServiceClient kmsClient, String keyName) {
      this.kmsClient = kmsClient;
      this.keyName = keyName;
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
        throws GeneralSecurityException {
      try {
        com.google.cloud.kms.v1.EncryptRequest encryptRequest =
            com.google.cloud.kms.v1.EncryptRequest.newBuilder()
                .setName(keyName)
                .setPlaintext(ByteString.copyFrom(plaintext))
                .setAdditionalAuthenticatedData(ByteString.copyFrom(associatedData))
                .build();

        com.google.cloud.kms.v1.EncryptResponse encResponse = kmsClient.encrypt(encryptRequest);
        return encResponse.getCiphertext().toByteArray();
      } catch (ApiException e) {
        throw new GeneralSecurityException("encryption failed", e);
      }
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
        throws GeneralSecurityException {
      try {
        com.google.cloud.kms.v1.DecryptRequest decryptRequest =
            com.google.cloud.kms.v1.DecryptRequest.newBuilder()
                .setName(keyName)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setAdditionalAuthenticatedData(ByteString.copyFrom(associatedData))
                .build();

        com.google.cloud.kms.v1.DecryptResponse decResponse = kmsClient.decrypt(decryptRequest);
        return decResponse.getPlaintext().toByteArray();
      } catch (ApiException e) {
        throw new GeneralSecurityException("decryption failed", e);
      }
    }
  }

  /**
   * A Builder to create an Aead backed by GCP Cloud KMS.
   *
   * <p>If {@link #setKeyManagementServiceClient} is used, the Aead will communicate with Cloud KMS
   * via gRPC given a {@link KeyManagementServiceClient} instance. If {@link #setCloudKms} is used,
   * the Aead will communicate with Cloud KMS via HTTP given a {@link CloudKMS} instance.
   *
   * <p>For new users we recommend using {@link #setKeyManagementServiceClient}.
   */
  public static final class Builder {
    @Nullable private String keyName = null;
    @Nullable private CloudKMS kmsClientHttp = null;
    @Nullable private KeyManagementServiceClient kmsClientGrpc = null;
    private static final String KEY_NAME_PATTERN =
        "projects/([^/]+)/locations/([a-zA-Z0-9_-]{1,63})/keyRings/"
            + "[a-zA-Z0-9_-]{1,63}/cryptoKeys/[a-zA-Z0-9_-]{1,63}";
    private static final Pattern KEY_NAME_MATCHER = Pattern.compile(KEY_NAME_PATTERN);

    private Builder() {}

    /** Set the ResourceName of the KMS key. */
    @CanIgnoreReturnValue
    public Builder setKeyName(String keyName) {
      this.keyName = keyName;
      return this;
    }

    /** Set the CloudKms object. */
    @CanIgnoreReturnValue
    public Builder setCloudKms(CloudKMS cloudKms) {
      this.kmsClientHttp = cloudKms;
      return this;
    }

    /** Set the KeyManagementServiceClient object. */
    @CanIgnoreReturnValue
    public Builder setKeyManagementServiceClient(KeyManagementServiceClient kmsClient) {
      this.kmsClientGrpc = kmsClient;
      return this;
    }

    public Aead build() throws GeneralSecurityException {
      if (keyName == null) {
        throw new GeneralSecurityException("The keyName is null.");
      }

      if (keyName.isEmpty()) {
        throw new GeneralSecurityException("The keyName is empty.");
      }

      if (!KEY_NAME_MATCHER.matcher(keyName).matches()) {
        throw new GeneralSecurityException("The keyName must follow " + KEY_NAME_PATTERN);
      }

      if (kmsClientGrpc == null && kmsClientHttp == null) {
        throw new GeneralSecurityException(
            "Either the CloudKMS or the KeyManagementServiceClient object must be provided.");
      }

      if (kmsClientGrpc != null && kmsClientHttp != null) {
        throw new GeneralSecurityException(
            "Either the CloudKMS or the KeyManagementServiceClient object must be provided.");
      }

      if (kmsClientHttp != null) {
        return new GcpKmsAead(kmsClientHttp, keyName);
      }

      return new GcpKmsAeadGrpc(kmsClientGrpc, keyName);
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
