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

import com.google.k2crypto.SymmetricKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class represents an AES key version in K2. It allows you to encrypt and decrypt messaged
 * using AES symmetric key encryption
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class AESKeyVersion extends SymmetricKey {
  /**
   * The key length in bytes (128 bits / 8 = 16 bytes) Can be 16, 24 or 32 (NO OTHER VALUES)
   */
  final int keyLength = 16;

  /**
   * SecretKey object representing the key matter in the AES key
   */
  SecretKey secretKey;

  /**
   * The actual key matter of the AES key used by encKey.
   */
  private byte[] keyMatter = new byte[keyLength];


  /**
   * initialization vector used for encryption and decryption
   */
  private byte[] initvector = new byte[16];

  /**
   * Supported modes: CBC, ECB, OFB, CFB, CTR Unsupported modes: XTS, OCB
   */
  final String mode = "CBC";

  /**
   * Supported padding: PKCS5PADDING
   * Unsupported padding: PKCS7Padding, ISO10126d2Padding, X932Padding, ISO7816d4Padding, ZeroBytePadding
   */
  final String padding = "PKCS5PADDING";
  
  /**
   * represents the algorithm, mode, and padding to use TODO: change this to allow different modes
   * and paddings (NOT algos - AES ONLY)
   * 
   */
  final String algModePadding = "AES/" + this.mode + "/" + padding;


  /**
   * The main method to test the other methods in this class
   *
   * @param args Command line parameters (unused)
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   */
  public static void main(String[] args)
      throws NoSuchAlgorithmException,
      InvalidKeyException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {


    // test string that we will encrypt and then decrypt
    String testinput = "weak";
    // print input string
    System.out.println("Input: " + testinput);
    System.out.println();
    // create AES key
    AESKeyVersion key = new AESKeyVersion();
    // encrypt the test string
    byte[] encTxt = key.encryptString(testinput);
    // print out the encrypted string
    System.out.println("Encrypted string: " + encTxt);
    System.out.println();
    // decrypt the message
    String result = key.decryptString(encTxt);
    // print out decrypted message
    System.out.println("Decrypted string: " + result);


  }

  /**
   * Constructor for AESKey. Uses JCE crypto libraries to initialize key matter.
   *
   * @throws NoSuchAlgorithmException This exception is only thrown if someone changes "AES" to an
   *         invalid encryption algorithm. This should never be changed.
   */
  public AESKeyVersion() throws NoSuchAlgorithmException {
    // Generate the key using JCE crypto libraries
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(this.keyLengthInBits());
    secretKey = keyGen.generateKey();
    // save the keymatter to the local variable keyMatter
    this.keyMatter = secretKey.getEncoded();

    // use this secure random number generator to initialize the vector with random bytes
    SecureRandom prng = new SecureRandom();
    prng.nextBytes(initvector);
    // create the SecretKey object from the byte array
    secretKey = new SecretKeySpec(this.keyMatter, 0, this.keyLengthInBytes(), "AES");

  }

  /**
   * Create an AESKey from saved key matter byte array
   *
   * @param keyMatter The byte array representing the key matter
   */
  public AESKeyVersion(byte[] keyMatter, byte[] initvector) {
    this.setKeyMatter(keyMatter, initvector);
  }

  /**
   * Method to give length of key in BITS. Used to prevent mixing up bytes and bits
   *
   * @return Key length in BITS
   */
  private int keyLengthInBits() {
    return this.keyLength * 8;
  }

  /**
   * Takes an array of bytes and encrypts it using the AES key
   *
   * @param data The byte array of data that we want to encrypt
   * @return Byte array representation of the encrypted data
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] encryptBytes(byte[] data)
      throws NoSuchAlgorithmException,
      NoSuchPaddingException,
      InvalidKeyException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {
    /**
     * TODO: Change this so we can use different modes of operation (instead of CBC) and different
     * paddings instead of PKCS7 padding
     */
    // make an AES cipher that we can use for encryption
    Cipher encCipher = Cipher.getInstance(algModePadding);


    if (this.mode.equals("CBC") || this.mode.equals("OFB") || this.mode.equals("CFB")
        || this.mode.equals("CTR")) {
      // Initialize the cipher using the secret key of this class and the initialization vector
      encCipher.init(Cipher.ENCRYPT_MODE, this.secretKey, new IvParameterSpec(this.initvector));
    } else if (this.mode.equals("ECB")) {
      // Initialize the cipher using the secret key - ECB does NOT use an initialization vector
      encCipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
    }

    // encrypt the data
    byte[] encryptedData = encCipher.doFinal(data);

    // return the encrypted data
    return encryptedData;
  }

  /**
   * Method to decrypt an encrypted byte array using the AES key
   *
   * @param data The encrypted input data that we want to decrypt
   * @return The byte array representation of the decrypted data
   * @throws InvalidKeyException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  public byte[] decryptBytes(byte[] data)
      throws InvalidKeyException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException,
      NoSuchAlgorithmException,
      NoSuchPaddingException {
    /**
     * TODO: Change this so we can use different modes of operation (instead of CBC) and different
     * paddings instead of PKCS7 padding
     */
    // make an AES cipher that we can use for decryption
    Cipher decCipher = Cipher.getInstance(algModePadding);


    if (this.mode.equals("CBC") || this.mode.equals("OFB") || this.mode.equals("CFB")
        || this.mode.equals("CTR")) {
      // Initialize the cipher using the secret key of this class and the initialization vector
      decCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initvector));
    } else if (this.mode.equals("ECB")) {
      // Initialize the cipher using the secret key - ECB does NOT use an initialization vector
      decCipher.init(Cipher.DECRYPT_MODE, secretKey);
    }


    // decrypt the data
    byte[] decryptedData = decCipher.doFinal(data);
    // return decrypted byte array
    return decryptedData;
  }

  /**
   * Method that decrypts an encrypted string
   *
   * @param input byte array representation of encrypted message
   * @return String representation of decrypted message
   * @throws InvalidKeyException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  public String decryptString(byte[] input)
      throws InvalidKeyException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException,
      NoSuchAlgorithmException,
      NoSuchPaddingException {
    // call decrypt bytes method
    byte[] outputData = this.decryptBytes(input);
    // convert to string
    String result = new String(outputData);
    // return result
    return result;
  }

  /**
   * Method to encrypt a string using the AES key
   *
   * @param input The input string that we want to encrypt
   * @return The byte array representation of the AES encrypted version of the string
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
  public byte[] encryptString(String input)
      throws InvalidKeyException,
      NoSuchAlgorithmException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {
    // Convert the input string to bytes
    byte[] data = input.getBytes();
    // call the encrypt bytes method to encrypt the data
    byte[] encData = this.encryptBytes(data);

    // return the encrypted string
    return encData;
  }

  /**
   * Method to return the key matter to other classes.
   *
   * @return The byte array representation of the key matter
   */
  public byte[] getKeyMatter() {
    return this.keyMatter;
  }

  /**
   * Initializes the key using key matter and initialization vector parameters.
   *
   * @param keymatter Byte array representation of a key we want to use
   * @param initvector Byte array representation of initialization vector.
   */
  public void setKeyMatter(byte[] keyMatter, byte[] initvector) {

    // save key matter byte array in this object
    this.keyMatter = keyMatter;
    // load the initialization vector
    this.initvector = initvector;

    // initialize secret key using key matter byte array
    secretKey = new SecretKeySpec(this.keyMatter, 0, this.keyLengthInBytes(), "AES");

  }

  /**
   * Method to return the initialization vector to other classes.
   *
   * @return The byte array representation of the initialization vector
   */
  public byte[] getInitVector() {
    return this.initvector;
  }

  /**
   *
   * Method to give length of key in BYTES. Used to prevent mixing up bytes and bits
   *
   * @return Key length in BYTES
   */
  private int keyLengthInBytes() {
    return this.keyLength;
  }
}
