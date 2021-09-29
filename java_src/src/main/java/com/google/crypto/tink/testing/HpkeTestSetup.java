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

package com.google.crypto.tink.testing;

import com.google.crypto.tink.subtle.Hex;

/** Helper class that contains setup parameter values for individual test vector. */
public final class HpkeTestSetup {
  public byte[] info; // info
  public byte[] senderPrivateKey; // skEm
  public byte[] recipientPublicKey; // pkRm
  public byte[] recipientPrivateKey; // skRm
  public byte[] encapsulatedKey; // enc
  public byte[] sharedSecret; // shared_secret
  public byte[] key; // key
  public byte[] baseNonce; // base_nonce

  public HpkeTestSetup(
      String info,
      String senderPrivateKey,
      String recipientPublicKey,
      String recipientPrivateKey,
      String encapsulatedKey,
      String sharedSecret,
      String key,
      String baseNonce) {
    this.info = Hex.decode(info);
    this.senderPrivateKey = Hex.decode(senderPrivateKey);
    this.recipientPublicKey = Hex.decode(recipientPublicKey);
    this.recipientPrivateKey = Hex.decode(recipientPrivateKey);
    this.encapsulatedKey = Hex.decode(encapsulatedKey);
    this.sharedSecret = Hex.decode(sharedSecret);
    this.key = Hex.decode(key);
    this.baseNonce = Hex.decode(baseNonce);
  }

  @Override
  public String toString() {
    String s = "";
    s += "info: " + Hex.encode(info) + "\n";
    s += "skEm: " + Hex.encode(senderPrivateKey) + "\n";
    s += "pkRm: " + Hex.encode(recipientPublicKey) + "\n";
    s += "skRm: " + Hex.encode(recipientPrivateKey) + "\n";
    s += "enc: " + Hex.encode(encapsulatedKey) + "\n";
    s += "shared_secret: " + Hex.encode(sharedSecret) + "\n";
    s += "key: " + Hex.encode(key) + "\n";
    s += "base_nonce: " + Hex.encode(baseNonce);
    return s;
  }
}
