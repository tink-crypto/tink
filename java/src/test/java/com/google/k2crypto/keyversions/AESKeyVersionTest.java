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

import com.google.k2crypto.SymmetricEncryption;
import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.DecryptionException;
import com.google.k2crypto.exceptions.EncryptionException;
import com.google.k2crypto.keyversions.AESKeyVersion.Mode;
import com.google.k2crypto.keyversions.AESKeyVersion.Padding;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionData;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Tests for AESkeyVersion class
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class AESKeyVersionTest {
  
  /**
   * Tests that the AESKeyVersion correctly saves to and loads from proto data. 
   */
  @Test
  public void testSaveLoad()
      throws BuilderException, InvalidProtocolBufferException {
    
    // Just generate a key version (use non-defaults where possible)
    AESKeyVersion toSave = new AESKeyVersion.Builder().mode(Mode.ECB).build();
    // Dump its proto data bytes
    ByteString bytes = toSave.buildData().build().toByteString();
    
    // Create a proto extension registry and register AES extension
    // (this will normally be done by KeyVersionRegistry)
    ExtensionRegistry registry = ExtensionRegistry.newInstance();
    AesKeyVersionProto.registerAllExtensions(registry);
    
    // Read the proto
    AESKeyVersion loaded = new AESKeyVersion.Builder()
        .withData(KeyVersionData.parseFrom(bytes, registry), registry).build();
    
    // Make sure the data is the same at a low-level (nothing gets lost)
    assertEquals(bytes, loaded.buildData().build().toByteString());

    // Make sure the important fields are all the same
    assertArrayEquals(
        toSave.getKeyVersionMatter(), loaded.getKeyVersionMatter());
    assertEquals(toSave.getAlgModePadding(), loaded.getAlgModePadding());
  }
  
  /**
   * This tests the encryption and decryption methods of the AESKeyVersion class.
   *
   * @throws BuilderException
   * @throws EncryptionException
   * @throws DecryptionException
   */
  @Test
  public void testEncryptDecrypt() throws BuilderException, EncryptionException,
      DecryptionException {

    // create AES key
    AESKeyVersion keyVersion =
        new AESKeyVersion.Builder().keyVersionLengthInBytes(16).build();
    // call the method to test encrypting and decrypting strings using this key version
    testEncryptDecryptKeyVersion(keyVersion);
  }

  /**
   * This tests loading a keyVersion matter byte array and using it to encrypt and decrypt a
   * message.
   *
   * @throws BuilderException
   * @throws EncryptionException
   * @throws DecryptionException
   */
  @Test
  public void testLoadkeyVersionMatter() throws BuilderException, EncryptionException,
      DecryptionException {
    // create AES key
    AESKeyVersion key1 =
        new AESKeyVersion.Builder().keyVersionLengthInBytes(16).build();
    // obtain the raw keyVersion matter
    byte[] keyVersionMatter = getkeyVersionMatter(key1);
    // obtain the raw initialization vector for first key
    byte[] initvector = getInitVector(key1);

    // create a new keyVersion using the keyVersion matter
    AESKeyVersion key2 = new AESKeyVersion.Builder().keyVersionLengthInBytes(16)
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
   * Test the AESKeyVersion encrypting and decrypting streams
   *
   * @throws BuilderException
   * @throws DecryptionException
   * @throws EncryptionException
   */
  @Test
  public void testAESKeyVersionStream() throws BuilderException, EncryptionException,
      DecryptionException {
    AESKeyVersion keyversion;

    /*
     *test all keyVersion version length WITHOUT mode
     */
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      // test keyVersion version length of 16 and PKCS5 padding and ECB mode
      keyversion = new AESKeyVersion.Builder()
          .keyVersionLengthInBytes(keyVersionLength)
          .padding(Padding.PKCS5).build();
      testEncryptDecryptStream(keyversion);

    }

    /*
     *test all keyVersion version length and mode combinations
     */
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      for (Mode mode : Mode.values()) {
        // test keyVersion version length of 16 and PKCS5 padding and ECB mode
        keyversion = new AESKeyVersion.Builder()
            .keyVersionLengthInBytes(keyVersionLength)
            .padding(Padding.PKCS5).mode(mode).build();
        testEncryptDecryptStream(keyversion);
      }
    }
  }

  /**
   * Helper method to test encrypting and decrypting a stream using an AESKeyVersion
   *
   * @param keyVersion The AESKeyVersion to use to encrypt and decrypt a stream
   * @throws EncryptionException
   * @throws DecryptionException
   */
  private void testEncryptDecryptStream(AESKeyVersion keyVersion) throws EncryptionException,
      DecryptionException {
    /*
     *test the encryption decryption STREAMS. Loop over an array of test input Strings to encrypt
     * and the decrypt
     */
    for (String testinput : new String[] {"weak", "test", "", "1234", "32980342yhio#$@^U"}) {
      // the input stream
      ByteArrayOutputStream inputStream = new ByteArrayOutputStream();

      // convert the test String to an input stream and encrypt it using the keyVersion
      SymmetricEncryption.encryptStream(keyVersion, new ByteArrayInputStream(testinput.getBytes()),
          inputStream);
      // convert the OutputStream (called inputStream) back to an InputStream (called
      // encryptedStream)
      ByteArrayInputStream encryptedStream = new ByteArrayInputStream(inputStream.toByteArray());

      // Initialize another OutputStream for our decrypted output
      ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();

      // use the keyVersion to decrypt the encrypted stream
      SymmetricEncryption.decryptStream(keyVersion, encryptedStream, decryptedStream);

      // convert the decrypted stream back to a String
      String output = new String(decryptedStream.toByteArray());

      // now check that the input matches the decrypted output
      assertEquals(testinput, output);
    }
  }

  /**
   * This tests creating an AESKeyVersion using the builder, then using that KeyVersion to encrypt
   * and decrypt a message
   *
   * @throws BuilderException
   * @throws EncryptionException
   * @throws DecryptionException
   */
  @Test
  public void testAESKeyVersionBuilder() throws BuilderException, EncryptionException,
      DecryptionException {

    // test using the default keyVersion builder
    AESKeyVersion keyversion = new AESKeyVersion.Builder().build();
    testEncryptDecryptKeyVersion(keyversion);

    /*
     *test all keyVersion version length WITHOUT mode
     */
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      // test keyVersion version length of 16 and PKCS5 padding and ECB mode
      keyversion = new AESKeyVersion.Builder()
          .keyVersionLengthInBytes(keyVersionLength)
          .padding(Padding.PKCS5).build();
      testEncryptDecryptKeyVersion(keyversion);

    }

    /*
     * test all keyVersion version length and mode combinations
     */
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      for (Mode mode : Mode.values()) {
        // test keyVersion version length of 16 and PKCS5 padding and ECB mode
        keyversion = new AESKeyVersion.Builder()
            .keyVersionLengthInBytes(keyVersionLength)
            .padding(Padding.PKCS5).mode(mode).build();
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
   * @throws EncryptionException
   * @throws DecryptionException
   */
  public void testEncryptDecryptKeyVersion(AESKeyVersion keyVersion) throws EncryptionException,
      DecryptionException {

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
    return kv.getKeyVersionMatter();
  }

  /**
   * Helper method to return the initialization vector to other classes.
   *
   * @param kv The AESKeyVersion from which we want to read the key version matter
   * @return The byte array representation of the initialization vector
   */
  private byte[] getInitVector(AESKeyVersion kv) {
    return kv.getInitVector();
  }

  /**
   * Helper method to encrypt a string using the AES key version. This is used to make testing
   * encrypting a byte array easier so we can read the input string and decrypted string easily.
   *
   * @param kv The AESKeyVersion that we want to use to encrypt the String
   * @param input The input string that we want to encrypt
   * @return The byte array representation of the AES encrypted version of the strings
   * @throws EncryptionException
   */
  private byte[] encryptString(AESKeyVersion kv, String input) throws EncryptionException {
    // Convert the input string to bytes
    byte[] data = input.getBytes();
    // call the encrypt bytes method to encrypt the data
    byte[] encData = SymmetricEncryption.encryptBytes(kv, data);

    // return the encrypted string
    return encData;
  }

  /**
   * Helper method that decrypts an encrypted string
   *
   * @param kv The AESKeyVersion that we want to use to decrypt the String
   * @param input byte array representation of encrypted message
   * @return String representation of decrypted message
   * @throws DecryptionException
   */
  private String decryptString(AESKeyVersion kv, byte[] input) throws DecryptionException {
    // call decrypt bytes method
    byte[] outputData = SymmetricEncryption.decryptBytes(kv, input);
    // convert to string
    String result = new String(outputData);
    // return result
    return result;
  }

}
