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

package com.google.crypto.tink.hybrid.internal.testing;

import com.google.crypto.tink.hybrid.HybridPrivateKey;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;

/** Test vector for Hybrid encryption. */
@Immutable
public final class HybridTestVector {
  public HybridTestVector(
      HybridPrivateKey privateKey, byte[] plaintext, byte[] contextInfo, byte[] ciphertext) {
    this.privateKey = privateKey;
    this.plaintext = Bytes.copyFrom(plaintext);
    this.contextInfo = Bytes.copyFrom(contextInfo);
    this.ciphertext = Bytes.copyFrom(ciphertext);
  }

  private final HybridPrivateKey privateKey;
  private final Bytes plaintext;
  private final Bytes contextInfo;
  private final Bytes ciphertext;

  public HybridPrivateKey getPrivateKey() {
    return privateKey;
  }

  public byte[] getPlaintext() {
    return plaintext.toByteArray();
  }

  public byte[] getContextInfo() {
    return contextInfo.toByteArray();
  }

  public byte[] getCiphertext() {
    return ciphertext.toByteArray();
  }
}
