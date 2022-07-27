// Copyright 2022 Google LLC
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

import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/** Private keys used in Diffie-Hellman-based X25519-HKDF HPKE KEM variant. */
@Immutable
final class X25519HpkeKemPrivateKey implements HpkeKemPrivateKey {
  private final Bytes privateKey;
  private final Bytes publicKey;

  static X25519HpkeKemPrivateKey fromBytes(byte[] privateKey) throws GeneralSecurityException {
    return new X25519HpkeKemPrivateKey(privateKey, X25519.publicFromPrivate(privateKey));
  }

  private X25519HpkeKemPrivateKey(byte[] privateKey, byte[] publicKey) {
    this.privateKey = Bytes.copyFrom(privateKey);
    this.publicKey = Bytes.copyFrom(publicKey);
  }

  @Override
  public Bytes getSerializedPrivate() {
    return privateKey;
  }

  @Override
  public Bytes getSerializedPublic() {
    return publicKey;
  }
}
