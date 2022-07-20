// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.aead.internal.InsecureNonceAesGcmJce;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/** AES-GCM HPKE AEAD variant. */
@Immutable
final class AesGcmHpkeAead implements HpkeAead {
  private final int keyLength;

  AesGcmHpkeAead(int keyLength) throws InvalidAlgorithmParameterException {
    if ((keyLength != 16) && (keyLength != 32)) {
      throw new InvalidAlgorithmParameterException("Unsupported key length: " + keyLength);
    }
    this.keyLength = keyLength;
  }

  @Override
  public byte[] seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
      throws GeneralSecurityException {
    if (key.length != keyLength) {
      throw new InvalidAlgorithmParameterException("Unexpected key length: " + key.length);
    }
    InsecureNonceAesGcmJce aead = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
    return aead.encrypt(nonce, plaintext, associatedData);
  }

  @Override
  public byte[] open(byte[] key, byte[] nonce, byte[] ciphertext, byte[] associatedData)
      throws GeneralSecurityException {
    if (key.length != keyLength) {
      throw new InvalidAlgorithmParameterException("Unexpected key length: " + key.length);
    }
    InsecureNonceAesGcmJce aead = new InsecureNonceAesGcmJce(key, /*prependIv=*/ false);
    return aead.decrypt(nonce, ciphertext, associatedData);
  }

  @Override
  public byte[] getAeadId() throws GeneralSecurityException {
    switch (keyLength) {
      case 16:
        return HpkeUtil.AES_128_GCM_AEAD_ID;
      case 32:
        return HpkeUtil.AES_256_GCM_AEAD_ID;
      default:
        throw new GeneralSecurityException("Could not determine HPKE AEAD ID");
    }
  }

  @Override
  public int getKeyLength() {
    return keyLength;
  }

  @Override
  public int getNonceLength() {
    return 12;
  }
}
