/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.k2crypto.keyversions;

import javax.crypto.Cipher;

/**
 * This class represents a SymmetricKeyVersion in K2. It is abstract and extended by specific
 * symmetric key version implementations such as AESKey
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public abstract class SymmetricKeyVersion extends KeyVersion {

  /**
   * Passes on the Builder to initialize the KeyVersion super-class. 
   * 
   * @param builder Builder from sub-class creation.
   */
  protected SymmetricKeyVersion(Builder builder) {
    super(builder);
  }
  
  /**
   * Method that returns the symmetric key version's encrypting Cipher
   *
   * @return The Cipher used to encrypt data
   */
  public abstract Cipher getEncryptingCipher();

  /**
   * Method that returns the symmetric key version's decrypting Cipher
   *
   * @return The Cipher used to decrypt data
   */
  public abstract Cipher getDecryptingCipher();
}
