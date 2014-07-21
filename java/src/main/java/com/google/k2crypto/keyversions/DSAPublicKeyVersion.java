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

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.EncryptionException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Class representing a DSA public key version in K2. It allows you to digitally verify data using
 * the DSA digital signature algorithm
 *
 * @author John Maheswaran (maheswaran@google.com)
 */

public class DSAPublicKeyVersion extends PublicKeyVersion {

  /**
   * The public key part for this DSAPublicKeyVersion
   */
  private PublicKey publicKeyPart;

  /**
   * Constructor for DSAPublicKeyVersion to build a DSAPublicKeyVersion using the Builder parameter
   *
   * @param builder A Builder object with values set, used to initialize this DSAPublicKeyVersion
   * @throws BuilderException
   */
  protected DSAPublicKeyVersion(Builder builder) throws BuilderException {
    super(builder);

    // check that we actually have a public key part otherwise throw an exception (cannot generate
    // public key without corresponding private key)
    if (builder.publicKeyPart == null) {
      throw new BuilderException(
          "Cannot initialize DSAPublicKeyVersion without PublicKey being set in the Builder");
    }

    // set the public key part
    this.publicKeyPart = builder.publicKeyPart;
  }

  /**
   * Method to verify a DSA digital signature
   *
   * @param data The data that was signed
   * @param sig The DSA digital signature itself
   * @return True if and only if the signature can be successfully verified against the input data
   *         using the public key. False otherwise.
   * @throws EncryptionException
   */
  public boolean verifySig(byte[] data, byte[] sig) throws EncryptionException {
    try {
      // Get a DSA signer using SHA1 as the hash function

      Signature signer = Signature.getInstance("SHA1withDSA");
      // initialize the signer using the public key
      signer.initVerify(this.publicKeyPart);
      // add the input data to the signer
      signer.update(data);
      // verify the signature on the input data using the private key and return it
      return (signer.verify(sig));
    } catch (GeneralSecurityException e) {
      // catch any exceptions and throw a K2 exception
      throw new EncryptionException("DSA verification failed unexpectedly", e);
    }

  }


  /**
   * Builder class used to build DSAPublicKeyVersion objects. Follows the builder design pattern.
   *
   * @author John Maheswaran (maheswaran@google.com)
   */
  public static class Builder extends KeyVersion.Builder {
    /**
     * The public key part for this DSAPublicKeyVersion
     */
    private PublicKey publicKeyPart;

    /**
     * Method to set the public key part
     *
     * @param publicKeyPart
     */
    public Builder setPublic(PublicKey publicKeyPart) {
      this.publicKeyPart = publicKeyPart;
      return this;
    }

    /**
     * Method to return a new public key version using the builder
     *
     * @return A new DSAPublicKeyVersion build using this Builder
     * @throws BuilderException
     */
    @Override
    public DSAPublicKeyVersion build() throws BuilderException {
      return new DSAPublicKeyVersion(this);
    }

  }

}
