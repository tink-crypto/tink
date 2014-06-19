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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;

import com.google.k2crypto.keyversions.AESKeyVersion;

import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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
    AESKeyVersion keyVersion = new AESKeyVersion();
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
    AESKeyVersion key1 = new AESKeyVersion();
    // obtain the raw keyVersion matter
    byte[] keyVersionMatter = key1.getkeyVersionMatter();
    // obtain the raw initialization vector for first key
    byte[] initvector = key1.getInitVector();

    // create a new keyVersion using the keyVersion matter
    AESKeyVersion key2 = new AESKeyVersion(keyVersionMatter, initvector);

    // test text string that we will encrypt and then decrypt
    String testinput = "weak";

    // encrypt the test string using FIRST key
    byte[] encTxt1 = key1.encryptString(testinput);
    // encrypt the test string using SECOND key
    byte[] encTxt2 = key2.encryptString(testinput);


    // test encrypted messages are the same
    assertArrayEquals(encTxt1, encTxt2);

    // test that keyVersion 1 decrypts encrypted message 1
    assertEquals(testinput, key1.decryptString(encTxt1));
    // test that keyVersion 2 decrypts encrypted message 2
    assertEquals(testinput, key2.decryptString(encTxt2));
    // test that keyVersion 2 decrypts encrypted message 1
    assertEquals(testinput, key2.decryptString(encTxt1));
    // test that keyVersion 1 decrypts encrypted message 2
    assertEquals(testinput, key1.decryptString(encTxt2));

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
      keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(keyVersionLength)
          .padding("PKCS5PADDING").build();
      testEncryptDecryptKeyVersion(keyversion);

    }

    // ////////////////////////////
    // test all keyVersion version length and mode combinations
    // ////////////////////////////
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      for (String mode : new String[] {"ECB", "CBC", "OFB", "CFB", "CTR"}) {
        // test keyVersion version length of 16 and PKCS5 padding and ECB mode
        keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(keyVersionLength)
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
    byte[] encTxt = keyVersion.encryptString(testinput);
    // decrypt the message
    String result = keyVersion.decryptString(encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);

    // empty string test
    testinput = "";
    // encrypt the test string
    encTxt = keyVersion.encryptString(testinput);
    // decrypt the message
    result = keyVersion.decryptString(encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);


  }
}
