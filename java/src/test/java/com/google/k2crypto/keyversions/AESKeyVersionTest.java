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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.google.k2crypto.keyversions.AESKeyVersion.Mode;

import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Tests for AESkeyVersion class
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class AESKeyVersionTest {
  /**
   * This tests the encryption and decryption methods of the AESKeyVersion class.
   *
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  @Test
  public void testEncryptDecrypt()
      throws NoSuchAlgorithmException,
      InvalidKeyException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {

    // create AES key
    AESKeyVersion keyVersion =
        new AESKeyVersion.AESKeyVersionBuilder().keyVersionLengthInBytes(16).build();
    // call the method to test encrypting and decrypting strings using this key version
    testEncryptDecryptKeyVersion(keyVersion);

    // fail("Not yet implemented");

  }

  /**
   * This tests loading a keyVersion matter byte array and using it to encrypt and decrypt a
   * message.
   *
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   */
  @Test
  public void testLoadkeyVersionMatter()
      throws NoSuchAlgorithmException,
      InvalidKeyException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {
    // create AES key
    AESKeyVersion key1 = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLengthInBytes(16).build();
    // obtain the raw keyVersion matter
    byte[] keyVersionMatter = getkeyVersionMatter(key1);
    // obtain the raw initialization vector for first key
    byte[] initvector = getInitVector(key1);

    // create a new keyVersion using the keyVersion matter
    AESKeyVersion key2 = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLengthInBytes(16)
        .matterVector(keyVersionMatter, initvector).build();

    // test text string that we will encrypt and then decrypt
    String testinput = "weak";

    // encrypt the test string using FIRST key
    byte[] encTxt1 = encryptString(key1, testinput);
    // encrypt the test string using SECOND key
    byte[] encTxt2 = encryptString(key2, testinput);

    // test encrypted messages are the same
    assertArrayEquals(encTxt1, encTxt2);

    // test that keyVersion 1 decrypts encrypted message 1
    assertEquals(testinput, decryptString(key1, encTxt1));
    // test that keyVersion 2 decrypts encrypted message 2
    assertEquals(testinput, decryptString(key2, encTxt2));
    // test that keyVersion 2 decrypts encrypted message 1
    assertEquals(testinput, decryptString(key2, encTxt1));
    // test that keyVersion 1 decrypts encrypted message 2
    assertEquals(testinput, decryptString(key1, encTxt2));

  }

  /**
   * This tests creating an AESKeyVersion using the builder, then using that KeyVersion to encrypt
   * and decrypt a message
   *
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   */
  @Test
  public void testAESKeyVersionBuilder()
      throws NoSuchAlgorithmException,
      InvalidKeyException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {

    // test using the default keyVersion builder
    AESKeyVersion keyversion = new AESKeyVersion.AESKeyVersionBuilder().build();
    testEncryptDecryptKeyVersion(keyversion);

    // ////////////////////////////
    // test all keyVersion version length WITHOUT mode
    // ////////////////////////////
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      // test keyVersion version length of 16 and PKCS5 padding and ECB mode
      keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLengthInBytes(keyVersionLength)
          .padding("PKCS5PADDING").build();
      testEncryptDecryptKeyVersion(keyversion);

    }

    // ////////////////////////////
    // test all keyVersion version length and mode combinations
    // ////////////////////////////
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      for (Mode mode : Mode.values()) {
        // test keyVersion version length of 16 and PKCS5 padding and ECB mode
        keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLengthInBytes(keyVersionLength)
            .padding("PKCS5PADDING").mode(mode).build();
        testEncryptDecryptKeyVersion(keyversion);
      }
    }

  }

  /**
   * This is a helper method used by the testAESKeyVersionBuilder test to testthe encryption and
   * decryption methods of the AESKeyVersion class using a SPECIFIC KEYVERSION (specified by the
   * parameter)
   *
   * @param keyVersion The AESKeyVersion to use to test encryption and decryption
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public void testEncryptDecryptKeyVersion(AESKeyVersion keyVersion)
      throws InvalidKeyException,
      NoSuchAlgorithmException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {

    // test text string that we will encrypt and then decrypt
    String testinput = "weak";
    // encrypt the test string
    byte[] encTxt = encryptString(keyVersion, testinput);
    // decrypt the message
    String result = decryptString(keyVersion, encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);

    // empty string test
    testinput = "";
    // encrypt the test string
    encTxt = encryptString(keyVersion, testinput);
    // decrypt the message
    result = decryptString(keyVersion, encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);
  }

  /**
   * Helper method to return the key version matter of an AESKeyVersion. Used to help test loading
   * an AESKeyVersion from a byte array
   *
   * @param kv The AESKeyVersion from which we want to read the key version matter
   * @return The byte array representation of the key version matter
   */
  private byte[] getkeyVersionMatter(AESKeyVersion kv) {
    return kv.keyVersionMatter;
  }

  /**
   * Helper method to return the initialization vector to other classes.
   *
   * @param kv The AESKeyVersion from which we want to read the key version matter
   * @return The byte array representation of the initialization vector
   */
  private byte[] getInitVector(AESKeyVersion kv) {
    return kv.initvector;
  }

  /**
   * Helper method to encrypt a string using the AES key version. This is used to make testing
   * encrypting a byte array easier so we can read the input string and decrypted string easily.
   *
   * @param kv The AESKeyVersion that we want to use to encrypt the String
   * @param input The input string that we want to encrypt
   * @return The byte array representation of the AES encrypted version of the string
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
  private byte[] encryptString(AESKeyVersion kv, String input)
      throws InvalidKeyException,
      NoSuchAlgorithmException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {
    // Convert the input string to bytes
    byte[] data = input.getBytes();
    // call the encrypt bytes method to encrypt the data
    byte[] encData = kv.encryptBytes(data);

    // return the encrypted string
    return encData;
  }

  /**
   * Helper method that decrypts an encrypted string
   *
   * @param kv The AESKeyVersion that we want to use to decrypt the String
   * @param input byte array representation of encrypted message
   * @return String representation of decrypted message
   * @throws InvalidKeyException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  private String decryptString(AESKeyVersion kv, byte[] input)
      throws InvalidKeyException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException,
      NoSuchAlgorithmException,
      NoSuchPaddingException {
    // call decrypt bytes method
    byte[] outputData = kv.decryptBytes(input);
    // convert to string
    String result = new String(outputData);
    // return result
    return result;
  }

}
