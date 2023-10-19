// Copyright 2023 Google LLC
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

package com.google.crypto.tink.signature.internal.testing;

import com.google.crypto.tink.signature.SignaturePrivateKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;

/** Test vectors for signatures. */
@Immutable
public final class SignatureTestVector {
  public SignatureTestVector(SignaturePrivateKey privateKey, byte[] message, byte[] signature) {
    this.privateKey = privateKey;
    this.message = Bytes.copyFrom(message);
    this.signature = Bytes.copyFrom(signature);
  }

  private final SignaturePrivateKey privateKey;
  private final Bytes signature;
  private final Bytes message;

  public SignaturePrivateKey getPrivateKey() {
    return privateKey;
  }

  public byte[] getSignature() {
    return signature.toByteArray();
  }

  public byte[] getMessage() {
    return message.toByteArray();
  }
}
