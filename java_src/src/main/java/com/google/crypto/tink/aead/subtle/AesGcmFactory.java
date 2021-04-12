// Copyright 2020 Google LLC
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

package com.google.crypto.tink.aead.subtle;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/** An {@link AeadFactory} that creates new instances of AES-GCM from raw keys */
@Immutable
public final class AesGcmFactory implements AeadFactory {
  private final int keySizeInBytes;

  public AesGcmFactory(int keySizeInBytes) throws GeneralSecurityException {
    this.keySizeInBytes = validateAesKeySize(keySizeInBytes);
  }

  @Override
  public int getKeySizeInBytes() {
    return keySizeInBytes;
  }

  @Override
  public Aead createAead(final byte[] symmetricKey) throws GeneralSecurityException {
    if (symmetricKey.length != getKeySizeInBytes()) {
      throw new GeneralSecurityException(
          String.format(
              "Symmetric key has incorrect length; expected %s, but got %s",
              getKeySizeInBytes(), symmetricKey.length));
    }
    return new AesGcmJce(symmetricKey);
  }

  /** @throws InvalidAlgorithmParameterException if {@code sizeInBytes} is not supported. */
  private static int validateAesKeySize(int sizeInBytes) throws InvalidAlgorithmParameterException {
    if (sizeInBytes != 16 && sizeInBytes != 32) {
      throw new InvalidAlgorithmParameterException(
          String.format("Invalid AES key size, expected 16 or 32, but got %d", sizeInBytes));
    }
    return sizeInBytes;
  }
}
