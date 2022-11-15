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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.Bytes;

/** Represents functions to encrypt and decrypt data using AEAD. */
public abstract class AeadKey extends Key {
  /**
   * Returns a {@link Bytes} instance which is prefixed to the ciphertext.
   *
   * <p>In order to make key rotation more efficient, Tink allows every Aead key to be prefixed with
   * a sequence of bytes. When decrypting data, only keys with matching prefix have to be tried.
   *
   * <p>Note that a priori, the output prefix may not be unique in a keyset (i.e., different keys in
   * a keyset may have the same prefix or, one prefix may be a prefix of the other). To avoid this,
   * built in Tink keys use the convention that the prefix is either '0x00<big endian key id>' or
   * '0x01<big endian key id>'. See the Tink keys for details.
   */
  public abstract Bytes getOutputPrefix();
  /** Returns the parameters of this key. */
  @Override
  public abstract AeadParameters getParameters();
}
