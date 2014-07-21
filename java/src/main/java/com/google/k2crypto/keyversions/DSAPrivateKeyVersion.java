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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Class representing a DSA private key version in K2. It allows you to digitally sign data using
 * the DSA digital signature algorithm
 *
 * @author John Maheswaran (maheswaran@google.com)
 *
 */

public class DSAPrivateKeyVersion extends PrivateKeyVersion {

  /**
   * The KeyPair for this DSA key version object
   */
  private KeyPair keyPair;


  /**
   * Constructor to make a DSAPrivateKeyVersion
   *
   * @param builder The Builder object passed in when creating the DSAPrivateKeyVersion
   * @throws BuilderException
   */
  protected DSAPrivateKeyVersion(Builder builder) throws BuilderException {
    super(builder);
    this.keyPair = this.generateKeyPair();
  }

  /**
   * Method to create a DSA digital signature
   *
   * @param inputData The input data that we want to sign
   * @return A byte array representing the DSA digital signature
   * @throws EncryptionException
   */
  public byte[] signData(byte[] inputData) throws EncryptionException {
    try {
      PrivateKey privateKey = this.getPrivate();

      // Get a DSA signer using SHA1 as the hash function
      Signature signer = Signature.getInstance("SHA1withDSA");
      // initialize the signer using the private key
      signer.initSign(privateKey);
      // add the input data to the signer
      signer.update(inputData);
      // sign the input data using the private key and return it
      return (signer.sign());
    } catch (GeneralSecurityException e) {
      // catch any exceptions and throw a K2 exception
      throw new EncryptionException("DSA signing failed", e);
    }
  }

  /**
   * Method to get the private key part of this DSA key version
   *
   * @return The PrivateKey for this DSA key version
   */
  private PrivateKey getPrivate() {
    return this.keyPair.getPrivate();
  }

  /**
   * Method to get the DSAPublicKeyVersion corresponding to this DSAPrivateKeyVersion
   *
   * @return The DSAPublicKeyVersion corresponding to this DSAPrivateKeyVersion
   * @throws BuilderException
   */
  public DSAPublicKeyVersion getPublic() throws BuilderException {
    return new DSAPublicKeyVersion.Builder().setPublic(this.keyPair.getPublic()).build();
  }


  /**
   * Method to generate a DSA key pair [NB: It takes up to 45 seconds to generate the key pair]
   * securely
   *
   * @return A fresh securely generated DSA KeyPair
   * @throws BuilderException
   */
  public KeyPair generateKeyPair() throws BuilderException {

    try {
      // get a DSA key pair generator
      KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DSA");
      // get a secure random number generator (note this is slow because it's secure)
      SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
      // initialize the key generator using the secure random number generator
      keyGenerator.initialize(1024, rng);
      // use the key generator to generate a key pair and return it
      return (keyGenerator.generateKeyPair());

    } catch (GeneralSecurityException e) {
      // catch and propagate any exceptions
      throw new BuilderException("Failed to build DSA key pair", e);
    }
  }

  /**
   * This class represents a key version builder for DSA key versions.
   *
   * @author John Maheswaran (maheswaran@google.com)
   */
  public static class Builder extends KeyVersion.Builder {

    /**
     * Method to build a new DSAPrivateKeyVersion
     *
     * @return An DSAPrivateKeyVersion with the parameters set from the builder
     * @throws BuilderException
     */
    @Override
    public DSAPrivateKeyVersion build() throws BuilderException {
      return new DSAPrivateKeyVersion(this);
    }

  }



}
