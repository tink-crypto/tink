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

import static com.google.common.io.BaseEncoding.base16;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.AWSKMSException;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.google.crypto.tink.Aead;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * This primitive forwards encryption/decryption requests to a key in AWS KMS.
 */
public final class AwsKmsAead implements Aead {

  /**
   * This client knows how to talk to AWS KMS.
   */
  private final AWSKMS kmsClient;

  // The location of a crypto key in AWS KMS.
  private final String kmsKeyArn;

  private AwsKmsAead(AWSKMS kmsClient, String kmsKeyArn) {
    this.kmsClient = kmsClient;
    this.kmsKeyArn = kmsKeyArn;
  }

  public static AwsKmsAead forEncryption(AWSKMS kmsClient, String kmsKeyArn) {
    return new AwsKmsAead(kmsClient, kmsKeyArn);
  }

  public static AwsKmsAead forDecryption(AWSKMS kmsClient) {
    return new AwsKmsAead(kmsClient, null /* kmsKeyArn, not needed for decryption */);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] aad)
      throws GeneralSecurityException {
    try {
      EncryptRequest req = new EncryptRequest()
          .withKeyId(kmsKeyArn)
          .withPlaintext(ByteBuffer.wrap(plaintext))
          .addEncryptionContextEntry("aad", base16().lowerCase().encode(aad));
      return kmsClient.encrypt(req).getCiphertextBlob().array();
    } catch (AWSKMSException e) {
      throw new GeneralSecurityException("encryption failed", e);
    }
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] aad)
      throws GeneralSecurityException {
    try {
      DecryptRequest req = new DecryptRequest()
          .withCiphertextBlob(ByteBuffer.wrap(ciphertext))
          .addEncryptionContextEntry("aad", base16().lowerCase().encode(aad));
      return kmsClient.decrypt(req).getPlaintext().array();
    } catch (AWSKMSException e) {
      throw new GeneralSecurityException("decryption failed", e);
    }
  }
}
