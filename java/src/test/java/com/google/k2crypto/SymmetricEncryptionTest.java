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

package com.google.k2crypto;

import static org.junit.Assert.assertEquals;

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.DecryptionException;
import com.google.k2crypto.exceptions.EncryptionException;
import com.google.k2crypto.keyversions.AESKeyVersion;
import com.google.k2crypto.keyversions.AESKeyVersion.Padding;
import com.google.k2crypto.keyversions.SymmetricKeyVersion;
import com.google.k2crypto.keyversions.AESKeyVersion.Mode;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * This class tests symmetric encryption in K2.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class SymmetricEncryptionTest {

  /**
   * This tests encryption and decryption using an AESKeyVersion through the SymmetricEncryption
   * class
   *
   * @throws BuilderException
   * @throws EncryptionException
   */
  @Test
  public void testEncryptDecrypt() throws DecryptionException, BuilderException,
      EncryptionException {

    // test using the default keyVersion builder
    AESKeyVersion keyversion = new AESKeyVersion.Builder().build();
    testEncryptDecryptKeyVersion(keyversion);

    // test all keyVersion version length WITHOUT mode
    for (Integer keyVersionLength : new Integer[] {16, 24, 32}) {
      // test keyVersion version length of 16 and PKCS5 padding and ECB mode
      keyversion = new AESKeyVersion.Builder()
          .keyVersionLengthInBytes(keyVersionLength)
          .padding(Padding.PKCS5).build();
      testEncryptDecryptKeyVersion(keyversion);

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
        testEncryptDecryptKeyVersion(keyversion);
      }
    }

  }

  /**
   * This is a helper method used by the testAESKeyVersionBuilder test to test the encryption and
   * decryption methods of the AESKeyVersion class using a SPECIFIC KEYVERSION (specified by the
   * parameter)
   *
   * @param keyVersion The AESKeyVersion to use to test encryption and decryption S
   * @throws EncryptionException
   * @throws DecryptionException
   */
  public void testEncryptDecryptKeyVersion(SymmetricKeyVersion keyVersion)
      throws EncryptionException, DecryptionException {

    // loop over an array of test input Strings to encrypt and the decrypt
    for (String testinput : new String[] {"weak", "test", "", "1234", "32980342yhio#$@^U"}) {
      /*
       *test the encryption decryption OF BYTE ARRAYS
       */

// encrypt the test string
      byte[] encTxt = encryptString(keyVersion, testinput);
      // decrypt the message
      String result = decryptString(keyVersion, encTxt);
      // test that the decrypted result is the same as the encryption input
      assertEquals(testinput, result);


      /*
       *now test the encryption decryption STREAMS
       */

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
   * Helper method to encrypt a string using the AES key version. This is used to make testing
   * encrypting a byte array easier so we can read the input string and decrypted string easily.
   *
   * @param kv The AESKeyVersion that we want to use to encrypt the String
   * @param input The input string that we want to encrypt
   * @return The byte array representation of the AES encrypted version of the string
   * @throws EncryptionException
   */
  private byte[] encryptString(SymmetricKeyVersion kv, String input) throws EncryptionException {
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
  private String decryptString(SymmetricKeyVersion kv, byte[] input) throws DecryptionException {
    // call decrypt bytes method
    byte[] outputData = SymmetricEncryption.decryptBytes(kv, input);
    // convert to string
    String result = new String(outputData);
    // return result
    return result;
  }

}
