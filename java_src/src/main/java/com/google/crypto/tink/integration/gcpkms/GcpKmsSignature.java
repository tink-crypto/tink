package com.google.crypto.tink.integration.gcpkms;

import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.model.AsymmetricSignRequest;
import com.google.api.services.cloudkms.v1.model.AsymmetricSignResponse;
import com.google.api.services.cloudkms.v1.model.Digest;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.proto.HashType;

import java.io.IOException;
import java.security.GeneralSecurityException;


/**
 * A {@link PublicKeySign} that forwards digital signature requests to a key in <a
 * href="https://cloud.google.com/kms/">Google Cloud KMS</a>.
 *
 * <p>As of August 2017, Google Cloud KMS supports only P256-SHA256 or P384-SHA384
 * keys/hashing.
 *
 * @since 1.6.0
 */
public final class GcpKmsSignature implements PublicKeySign {
  /** This client knows how to talk to Google Cloud KMS. */
  private final CloudKMS kmsClient;

  // The location of a CryptoKey in Google Cloud KMS.
  // Valid values have this format: projects/*/locations/*/keyRings/*/cryptoKeys/*.
  // See https://cloud.google.com/kms/docs/object-hierarchy.
  private final String kmsKeyUri;

  // Hash algorithm to use for the `Digest` field.
  private final HashType hashAlgorithm;

  public GcpKmsSignature(CloudKMS kmsClient, String keyUri, HashType hashAlgo) throws GeneralSecurityException {
    this.kmsClient = kmsClient;
    this.kmsKeyUri = keyUri;
    this.hashAlgorithm = hashAlgo;
  }

  @Override
  public byte[] sign(byte[] data) throws GeneralSecurityException {
    try {
      Digest digest = new Digest();
      switch (this.hashAlgorithm) {
        case SHA256:
          digest.encodeSha256(data);
          break;
        case SHA384:
          digest.encodeSha384(data);
          break;
        default:
          throw new GeneralSecurityException(
              "must use one of SHA256 or SHA384 for KMS asymmetric signing, depending on key size");
      }

      AsymmetricSignRequest request =
          new AsymmetricSignRequest().setDigest(digest);
      AsymmetricSignResponse response =
          this.kmsClient
              .projects()
              .locations()
              .keyRings()
              .cryptoKeys()
              .cryptoKeyVersions()
              .asymmetricSign(this.kmsKeyUri, request)
              .execute();
      return response.decodeSignature();

    } catch (IOException e) {
      throw new GeneralSecurityException("signing failed", e);
    }
  }
}
