// Copyright 2022 Google LLC
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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.kms.AbstractAWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A partial, fake implementation of AWSKMS that only supports encrypt and decrypt.
 *
 * <p>It creates a new AEAD for every valid key ID. It can encrypt message for these valid key IDs,
 * but fails for all other key IDs. On decrypt, it tries out all its AEADs and returns the plaintext
 * and the key ID of the AEAD that can successfully decrypt it.
 */
final class FakeAwsKms extends AbstractAWSKMS {
  private final Map<String, Aead> aeads = new HashMap<>();

  private static byte[] serializeContext(Map<String, String> encryptionContext) {
    TreeMap<String, String> ordered = new TreeMap<>(encryptionContext);
    return ordered.toString().getBytes(UTF_8);
  }

  public FakeAwsKms(List<String> validKeyIds) throws GeneralSecurityException {
    for (String keyId : validKeyIds) {
      Aead aead = KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM")).getPrimitive(Aead.class);
      aeads.put(keyId, aead);
    }
  }

  @Override
  public EncryptResult encrypt(EncryptRequest request) {
    if (!aeads.containsKey(request.getKeyId())) {
      throw new AmazonServiceException(
          "Unknown key ID : " + request.getKeyId() + " is not in " + aeads.keySet());
    }
    try {
      Aead aead = aeads.get(request.getKeyId());
      byte[] ciphertext =
          aead.encrypt(
              request.getPlaintext().array(), serializeContext(request.getEncryptionContext()));
      return new EncryptResult()
          .withKeyId(request.getKeyId())
          .withCiphertextBlob(ByteBuffer.wrap(ciphertext));
    } catch (GeneralSecurityException e) {
      throw new AmazonServiceException(e.getMessage());
    }
  }

  @Override
  public DecryptResult decrypt(DecryptRequest request) {
    for (Map.Entry<String, Aead> entry : aeads.entrySet()) {
      try {
        byte[] plaintext =
            entry
                .getValue()
                .decrypt(
                    request.getCiphertextBlob().array(),
                    serializeContext(request.getEncryptionContext()));
        return new DecryptResult()
            .withKeyId(entry.getKey())
            .withPlaintext(ByteBuffer.wrap(plaintext));
      } catch (GeneralSecurityException e) {
        // try next key
      }
    }
    throw new AmazonServiceException("unable to decrypt");
  }
}
