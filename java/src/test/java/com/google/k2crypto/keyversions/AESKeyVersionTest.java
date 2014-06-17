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
 * Tests for AESKey class
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

    // test text string that we will encrypt and then decrypt
    String testinput = "weak";
    // create AES key
    AESKeyVersion key = new AESKeyVersion();
    // encrypt the test string
    byte[] encTxt = key.encryptString(testinput);
    // decrypt the message
    String result = key.decryptString(encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);

    // empty string test
    testinput = "";
    // create AES key
    key = new AESKeyVersion();
    // encrypt the test string
    encTxt = key.encryptString(testinput);
    // decrypt the message
    result = key.decryptString(encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);



    // fail("Not yet implemented");

  }

  /**
   * This tests loading a key matter byte array and using it to encrypt and decrypt a message.
   *
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   */
  @Test
  public void testLoadKeyMatter()
      throws NoSuchAlgorithmException,
      InvalidKeyException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {
    // create AES key
    AESKeyVersion key1 = new AESKeyVersion();
    // obtain the raw key matter
    byte[] keymatter = key1.getKeyMatter();
    // obtain the raw initialization vector for first key
    byte[] initvector = key1.getInitVector();

    // create a new key using the key matter
    AESKeyVersion key2 = new AESKeyVersion(keymatter, initvector);

    // test text string that we will encrypt and then decrypt
    String testinput = "weak";

    // encrypt the test string using FIRST key
    byte[] encTxt1 = key1.encryptString(testinput);
    // encrypt the test string using SECOND key
    byte[] encTxt2 = key2.encryptString(testinput);


    // test encrypted messages are the same
    assertArrayEquals(encTxt1, encTxt2);

    // test that key 1 decrypts encrypted message 1
    assertEquals(testinput, key1.decryptString(encTxt1));
    // test that key 2 decrypts encrypted message 2
    assertEquals(testinput, key2.decryptString(encTxt2));
    // test that key 2 decrypts encrypted message 1
    assertEquals(testinput, key2.decryptString(encTxt1));
    // test that key 1 decrypts encrypted message 2
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

    // test using the default key builder
    AESKeyVersion keyversion = new AESKeyVersion.AESKeyVersionBuilder().build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 16
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(16).build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 24
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(24).build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 32
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(32).build();
    testEncryptDecryptKeyVersion(keyversion);

    // ////////////////////////////
    // 16 bit key version length with all modes
    // ////////////////////////////

    // test key version length of 16 and PKCS5 padding
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(16)
        .padding("PKCS5PADDING").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 16 and PKCS5 padding and ECB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(16)
        .padding("PKCS5PADDING").mode("ECB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 16 and PKCS5 padding and CBC mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(16)
        .padding("PKCS5PADDING").mode("CBC").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 16 and PKCS5 padding and OFB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(16)
        .padding("PKCS5PADDING").mode("OFB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 16 and PKCS5 padding and CFB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(16)
        .padding("PKCS5PADDING").mode("CFB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 16 and PKCS5 padding and CTR mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(16)
        .padding("PKCS5PADDING").mode("CTR").build();
    testEncryptDecryptKeyVersion(keyversion);

    // ////////////////////////////
    // 24 bit key version length with all modes
    // ////////////////////////////

    // test key version length of 24 and PKCS5 padding and ECB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(24)
        .padding("PKCS5PADDING").mode("ECB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 24 and PKCS5 padding and CBC mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(24)
        .padding("PKCS5PADDING").mode("CBC").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 24 and PKCS5 padding and OFB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(24)
        .padding("PKCS5PADDING").mode("OFB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 24 and PKCS5 padding and CFB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(24)
        .padding("PKCS5PADDING").mode("CFB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 24 and PKCS5 padding and CTR mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(24)
        .padding("PKCS5PADDING").mode("CTR").build();
    testEncryptDecryptKeyVersion(keyversion);

    // ////////////////////////////
    // 32 bit key version length with all modes
    // ////////////////////////////

    // test key version length of 32 and PKCS5 padding and ECB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(32)
        .padding("PKCS5PADDING").mode("ECB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 32 and PKCS5 padding and CBC mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(32)
        .padding("PKCS5PADDING").mode("CBC").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 32 and PKCS5 padding and OFB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(32)
        .padding("PKCS5PADDING").mode("OFB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 32 and PKCS5 padding and CFB mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(32)
        .padding("PKCS5PADDING").mode("CFB").build();
    testEncryptDecryptKeyVersion(keyversion);

    // test key version length of 32 and PKCS5 padding and CTR mode
    keyversion = new AESKeyVersion.AESKeyVersionBuilder().keyVersionLength(32)
        .padding("PKCS5PADDING").mode("CTR").build();
    testEncryptDecryptKeyVersion(keyversion);


  }

  /**
   * This is a helper method used by the testAESKeyVersionBuilder test to testthe encryption and
   * decryption methods of the AESKeyVersion class using a SPECIFIC KEYVERSION (specified by the
   * parameter)
   *
   * @param key The AESKeyVersion to use to test encryption and decryption
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public void testEncryptDecryptKeyVersion(AESKeyVersion key)
      throws InvalidKeyException,
      NoSuchAlgorithmException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException {

    // test text string that we will encrypt and then decrypt
    String testinput = "weak";
    // encrypt the test string
    byte[] encTxt = key.encryptString(testinput);
    // decrypt the message
    String result = key.decryptString(encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);

    // empty string test
    testinput = "";
    // encrypt the test string
    encTxt = key.encryptString(testinput);
    // decrypt the message
    result = key.decryptString(encTxt);
    // test that the decrypted result is the same as the encryption input
    assertEquals(testinput, result);


  }
}
