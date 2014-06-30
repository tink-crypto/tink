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
import com.google.k2crypto.exceptions.SigningException;

import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class represents a hash key version in K2. It is abstract and extended by specific hash key
 * implementations such as HMACKeyVersion
 *
 * @author John Maheswaran (maheswaran@google.com)
 */

public class HMACKeyVersion extends HashKeyVersion {

  /**
   * The actual key matter of the HMAC key version. TODO: SHA1 and MD5 keys are both 64 bytes in
   * length. Are any HMAC keys not 64 bytes in length?
   */
  protected byte[] keyVersionMatter = new byte[64];

  /**
   * SecretKey object representing the key matter in the HMAC key version
   */
  private SecretKey secretKey;

  /**
   * Private constructor to ensure people use generateSHA1HMAC or generateMD5HMAC to generate HMAC
   * key
   */
  private HMACKeyVersion() {
    // Do not put any code here
  }

  /**
   * Generates a new HMAC using the SHA1 hash algorithm
   *
   * @return a new HMACKeyVersion using the SHA1 hash algorithm
   * @throws BuilderException
   */
  public static HMACKeyVersion generateSHA1HMAC() throws BuilderException {
    try {
      HMACKeyVersion hmac = new HMACKeyVersion();
      // Generate a key for the HMAC-SHA1 keyed-hashing algorithm
      KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
      hmac.secretKey = keyGen.generateKey();
      // save the byte array of the secret key
      hmac.keyVersionMatter = hmac.secretKey.getEncoded();
      return hmac;
    } catch (Exception e) {
      // throw builder exception if could not build key
      throw new BuilderException("Failed to build HMACKeyVersion", e);
    }
  }

  /**
   * Generates a new HMAC using the SHA1 hash algorithm from give keyversion matter
   *
   * @param keyVersionMatter The byte array representation of the HMAC key version
   * @return an HMACKeyVersion object representing the HMAC key based on the input key version
   *         matter
   * @throws BuilderException
   */
  public static HMACKeyVersion generateSHA1HMAC(byte[] keyVersionMatter) throws BuilderException {
    try {
      HMACKeyVersion hmac = new HMACKeyVersion();
      // save the byte array of the secret key
      hmac.keyVersionMatter = keyVersionMatter;
      // set the secret key based on the raw key matter
      hmac.secretKey = new SecretKeySpec(keyVersionMatter, 0, keyVersionMatter.length, "HmacSHA1");
      return hmac;
    } catch (Exception e) {
      // throw builder exception if could not build key
      throw new BuilderException("Failed to build HMACKeyVersion", e);
    }
  }

  /**
   * Generates a new HMAC using the MD5 hash algorithm
   *
   * @return a new HMACKeyVersion using the MD5 hash algorithm
   * @throws BuilderException
   */
  public static HMACKeyVersion generateMD5HMAC() throws BuilderException {
    try {
      HMACKeyVersion hmac = new HMACKeyVersion();
      // Generate a key for the HMAC-SHA1 keyed-hashing algorithm
      KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
      hmac.secretKey = keyGen.generateKey();
      // save the byte array of the secret key
      hmac.keyVersionMatter = hmac.secretKey.getEncoded();
      return hmac;
    } catch (Exception e) {
      // throw builder exception if could not build key
      throw new BuilderException("Failed to build HMACKeyVersion", e);
    }
  }

  /**
   * Public method to get the byte array of the HMAC key version matter
   *
   * @return The byte array representation of the HMAC key version matter
   */
  public byte[] getKeyVersionMatter() {
    return this.keyVersionMatter;
  }

  /**
   * Method to compute the raw HMAC on a piece of input data
   *
   * @param inputData The data on which to compute the HMAC
   * @return The byte array representation of the HMAC
   * @throws SigningException
   */
  public byte[] getRawHMAC(byte[] inputData) throws SigningException {
    try {
      // get an SHA1 HMAC Mac instance
      Mac mac = Mac.getInstance("HmacSHA1");
      // now initialize with the signing key it withthe key
      mac.init(this.secretKey);
      // compute the hmac on input data bytes
      byte[] hmacsig = mac.doFinal(inputData);
      // return the HMAC
      return hmacsig;
    } catch (Exception e) {
      // catch any exceptions and throw custom exception
      throw new SigningException("Failed to generate HMAC signature");
    }
  }

  /**
   * Method that verifies a given HMAC on a piece of data
   *
   * @param inputHmac The input HMAC to verify
   * @param message The input message to check the HMAC against
   * @return True if and only if the HMAC computed on the message matches the input HMAC, false
   *         otherwise
   * @throws SigningException
   */
  public boolean verifyHMAC(byte[] inputHmac, byte[] message) throws SigningException {
    // compute the hmac on the message
    // if the input hmac matches the computed hmac return true
    if (Arrays.equals(inputHmac, getRawHMAC(message))) {
      return true;
    }
    // otherwise return false as the computed hmac differs from the input hmac
    return false;
  }
}
