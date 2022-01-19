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

import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.SubtleUtil;
import java.math.BigInteger;

/** Helper class that represents single encryption from an individual test vector. */
public final class HpkeTestEncryption {
  public final BigInteger sequenceNumber;
  public final byte[] plaintext; // pt
  public final byte[] associatedData; // aad
  public final byte[] nonce; // nonce
  public final byte[] ciphertext; // ct

  public HpkeTestEncryption(byte[] baseNonce,
      String plaintext, String associatedData, String nonce, String ciphertext) {
    this.plaintext = Hex.decode(plaintext);
    this.associatedData = Hex.decode(associatedData);
    this.nonce = Hex.decode(nonce);
    this.ciphertext = Hex.decode(ciphertext);
    this.sequenceNumber = SubtleUtil.bytes2Integer(Bytes.xor(baseNonce, this.nonce));
  }

  @Override
  public String toString() {
    String s = "";
    s += "seqno: " + sequenceNumber + "\n";
    s += "pt: " + Hex.encode(plaintext) + "\n";
    s += "aad: " + Hex.encode(associatedData) + "\n";
    s += "nonce: " + Hex.encode(nonce) + "\n";
    s += "ct: " + Hex.encode(ciphertext);
    return s;
  }
}
