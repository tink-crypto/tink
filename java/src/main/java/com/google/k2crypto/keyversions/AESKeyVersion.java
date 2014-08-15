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
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionCore;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionData;
import com.google.k2crypto.keyversions.AesKeyVersionProto.AesKeyVersionCore;
import com.google.k2crypto.keyversions.AesKeyVersionProto.AesKeyVersionData;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class represents an AES key version in K2. It allows you to encrypt and
 * decrypt messaged using AES symmetric key encryption
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
@KeyVersionInfo(
    type = KeyVersionProto.Type.AES,
    proto = AesKeyVersionProto.class)
public class AESKeyVersion extends SymmetricKeyVersion {
  
  private static final int BLOCK_SIZE = 16; // bytes;
  
  /**
   * The key length in bytes (128 bits / 8 = 16 bytes) Can be 16, 24 or 32
   * (NO OTHER VALUES)
   */
  private int keyVersionLengthInBytes = 16;

  /**
   * SecretKey object representing the key matter in the AES key
   */
  private SecretKey secretKey;

  /**
   * initialization vector used for encryption and decryption
   */
  private byte[] initVector;

  /**
   * Enum representing all supported modes Supported modes:
   *    CBC, ECB, OFB, CFB, CTR Unsupported
   * modes: XTS, OCB
   */
  public enum Mode {
    CBC, ECB, OFB, CFB, CTR
  }

  /**
   * The encryption mode
   */
  private Mode mode;

  /**
   * Enum representing all supported padding modes.
   */
  public enum Padding {
    PKCS5
  }

  /**
   * Supported padding: PKCS5PADDING Unsupported padding: PKCS7Padding,
   * ISO10126d2Padding, X932Padding, ISO7816d4Padding, ZeroBytePadding
   */
  private Padding padding;

  /**
   * Method to give length of key in BITS. Used to prevent mixing up bytes
   * and bits
   *
   * @return Key length in BITS
   */
  private int keyLengthInBits() {
    return this.keyVersionLengthInBytes * 8;
  }

  /**
   *
   * Method to give length of key in BYTES. Used to prevent mixing up bytes
   * and bits
   *
   * @return Key length in BYTES
   */
  private int keyLengthInBytes() {
    return this.keyVersionLengthInBytes;
  }
  
  /**
   * represents the algorithm, mode, and padding to use and paddings
   * (NOT algorithm - AES ONLY)
   *
   */
  private String algModePadding;

  /**
   * Cipher for encrypting data using this AES key version
   */
  private Cipher encryptingCipher;

  /**
   * Cipher for decrypting data using this AES key version
   */
  private Cipher decryptingCipher;

  /**
   * Constructor to make an AESKeyVersion using the AESKeyVersionBuilder.
   * Private to prevent use unless through the AESKeyVersionBuilder
   *
   * @param builder An AESKeyVersionBuilder with all the variables set according
   *                to how you want the AESKeyVersion to be setup.
   * @throws BuilderException
   */
  private AESKeyVersion(Builder builder) throws BuilderException {
    super(builder);
    // set key version length, mode and padding based on the key version builder
    this.keyVersionLengthInBytes = builder.keyVersionLengthInBytes;
    this.mode = builder.mode;
    this.padding = builder.padding;

    // IMPORTANT! this line of code updates the algorithm/mode/padding string
    // to reflect the new mode and padding. The class will not work if you move
    // or remove this line of code
    this.algModePadding = "AES/" + this.mode + "/" + padding + "padding";

    // use try catch block to abstract from individual exceptions using
    // BuilderException
    try {
      // set the key matter and initialization vector from input if is
      // was provided
      if (builder.keyVersionMatterInitVectorProvided) {
        // load the initialization vector
        initVector = (builder.initVector == null ?
            null : builder.initVector.clone());

        // initialize secret key using key matter byte array
        secretKey = new SecretKeySpec(
            builder.keyVersionMatter, 0, this.keyLengthInBytes(), "AES");
        
      } else {
        // Generate the key using JCE crypto libraries
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(this.keyLengthInBits());
        secretKey = keyGen.generateKey();
      }
      
      if (initVector == null) {
        // use this secure random number generator to initialize
        // the vector with random bytes
        SecureRandom prng = new SecureRandom();
        initVector = new byte[BLOCK_SIZE];
        prng.nextBytes(initVector);        
      }

      // make an AES cipher that we can use for encryption
      this.encryptingCipher = Cipher.getInstance(this.algModePadding);

      // initialize the encrypting cipher
      switch (this.mode) {
        case ECB:
          // Initialize the cipher using the secret key -
          // ECB does NOT use an initialization vector
          encryptingCipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
          break;
        case CBC:
        case OFB:
        case CFB:
        case CTR:
          // Initialize the cipher using the secret key of this class
          // and the initialization vector
          encryptingCipher.init(Cipher.ENCRYPT_MODE, this.secretKey,
              new IvParameterSpec(this.initVector));
          break;
        default:
          throw new BuilderException("Unrecognized mode");
      }

      // make an AES cipher that we can use for decryption
      this.decryptingCipher = Cipher.getInstance(this.algModePadding);

      // initialize the decrypting cipher
      switch (this.mode) {
        case ECB:
          // Initialize the cipher using the secret key -
          // ECB does NOT use an initialization vector
          decryptingCipher.init(Cipher.DECRYPT_MODE, secretKey);
          break;
        case CBC:
        case OFB:
        case CFB:
        case CTR:
          // Initialize the cipher using the secret key of this class
          // and the initialization vector
          decryptingCipher.init(
              Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initVector));
          break;
        default:
          throw new BuilderException("Unrecognized mode");
      }

      // Catch all exceptions
    } catch (Exception e) {
      // Propagate the exception up using BuilderException
      throw new BuilderException("Building AESKeyVersion failed", e);
    }
  }
  
  /**
   * Public method to get the byte array of the AES key version matter
   *
   * @return The byte array representation of the AES key version matter
   */
  public byte[] getKeyVersionMatter() {
    return this.secretKey.getEncoded();
  }
  
  /**
   * Returns a copy of the IV.
   */
  public byte[] getInitVector() {
    return initVector.clone();
  }
  
  /**
   * Returns the algorithm, mode, and padding string passed to JCE.
   */
  public String getAlgModePadding() {
    return algModePadding;
  }
  
  /**
   * Method to get the encrypting cipher of this key version
   *
   * @return The Cipher object representing the encrypting cipher
   *         of this key version
   */
  @Override
  public Cipher getEncryptingCipher() {
    return this.encryptingCipher;
  }

  /**
   * Method to get the decrypting cipher of this key version
   *
   * @return The Cipher object representing the decrypting cipher
   *         of this key version
   */
  @Override
  public Cipher getDecryptingCipher() {
    return this.decryptingCipher;
  }

  /**
   * @see KeyVersion#buildCore()
   */
  @Override
  protected KeyVersionCore.Builder buildCore() {
    AesKeyVersionCore.Builder coreBuilder = AesKeyVersionCore.newBuilder();
    
    // Populate the core builder
    coreBuilder.setMatter(ByteString.copyFrom(secretKey.getEncoded()));
    
    // We can just use valueOf here because the enum constants have the same
    // names. This may not be the case for all key versions...
    coreBuilder.setBlockMode(KeyVersionProto.BlockMode.valueOf(mode.name()));
    coreBuilder.setPadding(KeyVersionProto.Padding.valueOf(padding.name()));
    
    KeyVersionCore.Builder builder = super.buildCore();
    builder.setExtension(AesKeyVersionCore.extension, coreBuilder.build());
    return builder;
  }
  
  /**
   * @see KeyVersion#buildData()
   */
  @Override
  public KeyVersionData.Builder buildData() {
    AesKeyVersionData.Builder dataBuilder = AesKeyVersionData.newBuilder();
    // TODO(darylseah): Populate the data builder
    
    KeyVersionData.Builder builder = super.buildData();
    builder.setExtension(AesKeyVersionData.extension, dataBuilder.build());
    return builder;
  }

  /**
   * This class represents a key version builder for AES key versions.
   *
   * @author John Maheswaran (maheswaran@google.com)
   */
  public static class Builder extends KeyVersion.Builder {
    /**
     * key size can be 16, 24 or 32
     */
    private int keyVersionLengthInBytes = 16;
    
    /**
     * Supported modes: CBC, ECB, OFB, CFB, CTR Unsupported modes: XTS, OCB
     */
    private Mode mode = Mode.CTR;

    /**
     * Supported paddings depends on Java implementation. Upgrade java
     * implementation to support more paddings. Supported padding: PKCS5PADDING
     * Unsupported padding: PKCS7Padding, ISO10126d2Padding, X932Padding,
     * ISO7816d4Padding, ZeroBytePadding
     */
    private Padding padding = Padding.PKCS5;

    /**
     * Byte array that will represent the key matter
     */
    private byte[] keyVersionMatter;
    
    /**
     * Byte array that will represent the initialization vector
     */
    private byte[] initVector;

    /**
     * Flag to indicate to the parent class (AESKeyVersion) whether the key
     * matter and initialization vector have been manually set (true if and
     * only if they have been manually set)
     */
    private boolean keyVersionMatterInitVectorProvided = false;

    /**
     * Set the key version length
     *
     * @param keyVersionLength Integer representing key version length in BYTES,
     *                         can be 16, 24, 32
     * @return This object with keyVersionLength updated
     */
    public Builder keyVersionLengthInBytes(int keyVersionLength) {
      this.keyVersionLengthInBytes = keyVersionLength;
      return this;
    }

    /**
     * Set the encryption mode
     *
     * @param mode representing the encryption mode.
     *             Supported modes: CBC, ECB, OFB, CFB, CTR
     * @return This object with mode updated
     */
    public Builder mode(Mode mode) {
      if (mode == null) {
        throw new NullPointerException("mode");
      }
      this.mode = mode;
      return this;
    }

    /**
     * Set the padding
     *
     * @param padding String representing the padding. Supported padding: PKCS5
     * @return This object with padding updated
     */
    public Builder padding(Padding padding) {
      if (padding == null) {
        throw new NullPointerException("padding");
      }
      this.padding = padding;
      return this;
    }

    /**
     *
     * @param keyVersionMatter Byte array representing the key matter
     * @param initVector Byte array representing the initialization vector
     * @return This object with key matter, initialization vector set
     */
    public Builder matterVector(byte[] keyVersionMatter, byte[] initVector) {
      if (keyVersionMatter == null) {
        throw new NullPointerException("keyVersionMatter");
      }
      
      // This flag indicates to the parent class (AESKeyVersion) that the
      // key matter and initialization vector have been manually set
      keyVersionMatterInitVectorProvided = true;
      // set the key matter
      this.keyVersionMatter = keyVersionMatter;
      // set the initialization vector
      this.initVector = initVector;
      // set derived key size
      keyVersionLengthInBytes = keyVersionMatter.length;
            
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
      AesKeyVersionData data = kvData.getExtension(AesKeyVersionData.extension);
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
      
      // Extract info from core
      AesKeyVersionCore core = kvCore.getExtension(AesKeyVersionCore.extension);
      this.matterVector(core.getMatter().toByteArray(), null);
      
      // valueOf()s below can fail if the mode/padding stored is unsupported 
      this.mode(Mode.valueOf(core.getBlockMode().name()));
      this.padding(Padding.valueOf(core.getPadding().name()));
      
      return this;
    }

    /**
     * Method to build a new AESKeyVersion
     *
     * @return An AESKeyVersion with the parameters set from the builder
     * @throws BuilderException
     */
    @Override
    public AESKeyVersion build() throws BuilderException {
      try {
        return new AESKeyVersion(this);
      } catch (Exception e) {
        throw new BuilderException("Building AESKeyVersion failed", e);
      }
    }
  }
}
