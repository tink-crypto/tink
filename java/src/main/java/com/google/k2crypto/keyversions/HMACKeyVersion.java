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
import com.google.k2crypto.keyversions.HmacKeyVersionProto.Algorithm;
import com.google.k2crypto.keyversions.HmacKeyVersionProto.HmacKeyVersionCore;
import com.google.k2crypto.keyversions.HmacKeyVersionProto.HmacKeyVersionData;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionCore;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionData;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;

import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class represents a hash key version in K2. It is abstract and extended
 * by specific hash key implementations such as HMACKeyVersion
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
@KeyVersionInfo(
    type = KeyVersionProto.Type.HMAC,
    proto = HmacKeyVersionProto.class)
public class HMACKeyVersion extends HashKeyVersion {
  /**
   * SecretKey object representing the key matter in the HMAC key version
   */
  private SecretKey secretKey;

  /**
   * Private constructor to ensure people use generateSHA1HMAC or
   * generateMD5HMAC to generate HMAC key
   */
  private HMACKeyVersion(Builder builder) throws Exception {
    super(builder);
    if (builder.keyVersionMatter == null) {
      // Generate a key for the HMAC-SHA1 keyed-hashing algorithm
      KeyGenerator keyGen = KeyGenerator.getInstance(builder.algorithm);
      secretKey = keyGen.generateKey();
    } else {
      // set the secret key based on the raw key matter
      secretKey = new SecretKeySpec(builder.keyVersionMatter,
          0, builder.keyVersionMatter.length, builder.algorithm);
    }
  }

  /**
   * String constants representing all supported hash algorithms.
   */
  public static final String HMAC_MD5 = "HmacMD5";
  public static final String HMAC_SHA1 = "HmacSHA1";
  public static final String HMAC_SHA256 = "HmacSHA256";
  public static final String HMAC_SHA384 = "HmacSHA384";
  public static final String HMAC_SHA512 = "HmacSHA512";

  /**
   * Hash algorithm for this HMAC key version
   */
  private String algorithm = HMAC_SHA1;

  /**
   * Generates a new HMAC using the SHA1 hash algorithm
   *
   * @return a new HMACKeyVersion using the SHA1 hash algorithm
   * @throws BuilderException
   */
  public static HMACKeyVersion generateHMAC(String hashAlgorithm)
      throws BuilderException {
    return new Builder().algorithm(hashAlgorithm).build();
  }

  /**
   * Generates a new HMAC using the SHA1 hash algorithm from give keyversion
   * matter
   *
   * @param keyVersionMatter The byte array representation of the
   *                         HMAC key version
   * @return an HMACKeyVersion object representing the HMAC key based on the
   *         input key version matter
   * @throws BuilderException
   */
  public static HMACKeyVersion generateHMAC(
      String hashAlgorithm, byte[] keyVersionMatter)
          throws BuilderException {
    return new Builder()
        .algorithm(hashAlgorithm).matterVector(keyVersionMatter).build();
  }

  /**
   * Public method to get the byte array of the HMAC key version matter
   *
   * @return The byte array representation of the HMAC key version matter
   */
  public byte[] getKeyVersionMatter() {
    return this.secretKey.getEncoded();
  }
  
  /**
   * Returns the digest algorithm for the HMAC. 
   */
  public String getAlgorithm() {
    return algorithm;
  }

  /**
   * Method to compute the raw HMAC on a piece of input data
   *
   * @param inputData The data on which to compute the HMAC
   * @return The byte array representation of the HMAC
   * @throws EncryptionException
   */
  public byte[] getRawHMAC(byte[] inputData) throws EncryptionException {
    try {
      // get an HMAC Mac instance using the algorithm of this HMAC key
      Mac mac = Mac.getInstance(this.algorithm);
      // now initialize with the signing key it withthe key
      mac.init(this.secretKey);
      // compute the hmac on input data bytes
      byte[] hmacsig = mac.doFinal(inputData);
      // return the HMAC
      return hmacsig;
    } catch (Exception e) {
      // catch any exceptions and throw custom exception
      throw new EncryptionException("Failed to generate HMAC signature", e);
    }
  }

  /**
   * Method that verifies a given HMAC on a piece of data
   *
   * @param inputHmac The input HMAC to verify
   * @param message The input message to check the HMAC against
   * @return True if and only if the HMAC computed on the message matches the
   *         input HMAC, false otherwise
   * @throws EncryptionException
   */
  public boolean verifyHMAC(byte[] inputHmac, byte[] message)
      throws EncryptionException {
    // compute the hmac on the message
    // if the input hmac matches the computed hmac return true
    if (Arrays.equals(inputHmac, getRawHMAC(message))) {
      return true;
    }
    // otherwise return false as the computed hmac differs from the input hmac
    return false;
  }
  
  /**
   * @see KeyVersion#buildCore()
   */
  @Override
  protected KeyVersionCore.Builder buildCore() {
    HmacKeyVersionCore.Builder coreBuilder = HmacKeyVersionCore.newBuilder();
    
    // Populate the core builder
    coreBuilder.setMatter(ByteString.copyFrom(secretKey.getEncoded()));

    // TODO: change this to an enum...
    if (algorithm.equalsIgnoreCase(HMAC_MD5)) {
      coreBuilder.setAlgorithm(Algorithm.MD5);  
    } else if (algorithm.equalsIgnoreCase(HMAC_SHA1)) {
      coreBuilder.setAlgorithm(Algorithm.SHA1);  
    } else if (algorithm.equalsIgnoreCase(HMAC_SHA256)) {
      coreBuilder.setAlgorithm(Algorithm.SHA2_256);  
    } else if (algorithm.equalsIgnoreCase(HMAC_SHA384)) {
      coreBuilder.setAlgorithm(Algorithm.SHA2_384);  
    } else if (algorithm.equalsIgnoreCase(HMAC_SHA512)) {
      coreBuilder.setAlgorithm(Algorithm.SHA2_512);  
    }
    
    KeyVersionCore.Builder builder = super.buildCore();
    builder.setExtension(HmacKeyVersionCore.extension, coreBuilder.build());
    return builder;
  }
  
  /**
   * @see KeyVersion#buildData()
   */
  @Override
  public KeyVersionData.Builder buildData() {
    HmacKeyVersionData.Builder dataBuilder = HmacKeyVersionData.newBuilder();
    // TODO(darylseah): Populate the data builder

    KeyVersionData.Builder builder = super.buildData();
    builder.setExtension(HmacKeyVersionData.extension, dataBuilder.build());
    return builder;
  }
  
  /**
   * This class represents a key version builder for HMAC key versions.
   *
   * @author John Maheswaran (maheswaran@google.com)
   */
  public static class Builder extends KeyVersion.Builder {
    /**
     * Hmac algorithm to use.
     */
    private String algorithm = HMAC_MD5;
    
    /**
     * Byte array that will represent the key matter
     */
    private byte[] keyVersionMatter;
    
    /**
     * Set the hash algorithm.
     *
     * @param hashAlgorithm Hash algorithm to use.
     * @return This object with algorithm updated.
     */
    public Builder algorithm(String hashAlgorithm) {
      if (hashAlgorithm.equalsIgnoreCase(HMAC_MD5)
          || hashAlgorithm.equalsIgnoreCase(HMAC_SHA1)
          || hashAlgorithm.equalsIgnoreCase(HMAC_SHA256)
          || hashAlgorithm.equalsIgnoreCase(HMAC_SHA384)
          || hashAlgorithm.equalsIgnoreCase(HMAC_SHA512)) {
        this.algorithm = hashAlgorithm;
        return this;
      } else {
        throw new IllegalArgumentException("Bad algorithm");
      }
    }

    /**
     * @param keyVersionMatter Byte array representing the key matter
     * @return This object with key matter set
     */
    public Builder matterVector(byte[] keyVersionMatter) {
      if (keyVersionMatter == null) {
        throw new NullPointerException("keyVersionMatter");
      }
      // set the key matter
      this.keyVersionMatter = keyVersionMatter;
      return this;
    }

    /**
     * @see KeyVersion.Builder#withData(KeyVersionData, ExtensionRegistry)
     */
    @Override
    public Builder withData(KeyVersionData kvData, ExtensionRegistry registry)
        throws InvalidProtocolBufferException {
      super.withData(kvData, registry);

      @SuppressWarnings("unused")
      HmacKeyVersionData data =
          kvData.getExtension(HmacKeyVersionData.extension);
      // TODO(darylseah): Extract info from data (currently not used)
      
      return this;
    }

    /**
     * @see KeyVersion.Builder#withCore(KeyVersionCore)
     */
    @Override
    protected Builder withCore(KeyVersionCore kvCore)
        throws InvalidProtocolBufferException {
      super.withCore(kvCore);
      
      HmacKeyVersionCore core =
          kvCore.getExtension(HmacKeyVersionCore.extension);
      // Extract info from core
      this.matterVector(core.getMatter().toByteArray());
      switch (core.getAlgorithm()) {
        case MD5:
          this.algorithm(HMAC_MD5);
          break;
        case SHA1:
          this.algorithm(HMAC_SHA1);
          break;
        case SHA2_256:
          this.algorithm(HMAC_SHA256);
          break;
        case SHA2_384:
          this.algorithm(HMAC_SHA384);
          break;
        case SHA2_512:
          this.algorithm(HMAC_SHA512);
          break;
        default:
          throw new IllegalArgumentException("Bad algorithm");
      }
      
      return this;
    }

    /**
     * Method to build a new HMACKeyVersion
     *
     * @return A HMACKeyVersion with the parameters set from the builder
     * @throws BuilderException
     */
    @Override
    public HMACKeyVersion build() throws BuilderException {
      try {
        return new HMACKeyVersion(this);
      } catch (Exception e) {
        throw new BuilderException("Building HMACKeyVersion failed", e);
      }
    }
  }
}
