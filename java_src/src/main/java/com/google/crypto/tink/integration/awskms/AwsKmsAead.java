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

package com.google.crypto.tink.integration.awskms;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.util.BinaryUtils;
import com.google.crypto.tink.Aead;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * A {@link Aead} that forwards encryption/decryption requests to a key in <a
 * href="https://aws.amazon.com/kms/">AWS KMS</a>.
 *
 * @since 1.0.0
 */
public final class AwsKmsAead implements Aead {

  /** This client knows how to talk to AWS KMS. */
  private final AWSKMS kmsClient;

  // The location of a crypto key in AWS KMS, without the aws-kms:// prefix.
  private final String keyArn;

  public AwsKmsAead(AWSKMS kmsClient, String keyUri) throws GeneralSecurityException {
    this.kmsClient = kmsClient;
    this.keyArn = keyUri;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      EncryptRequest req =
          new EncryptRequest().withKeyId(keyArn).withPlaintext(ByteBuffer.wrap(plaintext));
      if (associatedData != null && associatedData.length != 0) {
        req = req.addEncryptionContextEntry("associatedData", BinaryUtils.toHex(associatedData));
      }
      return kmsClient.encrypt(req).getCiphertextBlob().array();
    } catch (AmazonServiceException e) {
      throw new GeneralSecurityException("encryption failed", e);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    try {
      DecryptRequest req = new DecryptRequest().withCiphertextBlob(ByteBuffer.wrap(ciphertext));
      if (associatedData != null && associatedData.length != 0) {
        req = req.addEncryptionContextEntry("associatedData", BinaryUtils.toHex(associatedData));
      }
      DecryptResult result = kmsClient.decrypt(req);
      if (!result.getKeyId().equals(keyArn)) {
        throw new GeneralSecurityException("decryption failed: wrong key id");
      }
      return result.getPlaintext().array();
    } catch (AmazonServiceException e) {
      throw new GeneralSecurityException("decryption failed", e);
    }
  }
}
