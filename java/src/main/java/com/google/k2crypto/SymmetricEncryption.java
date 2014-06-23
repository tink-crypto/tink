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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;

/**
 * This class represents a symmetric encryption in a K2. It is extends Purpose and allows you to
 * actually encrypt and decrypt data using a SymmetricKey
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class SymmetricEncryption extends Purpose {

  /**
   * Encrypts a byte array using a symmetric key version
   *
   * @param keyVersion The symmetric key version to use to encrypt the data
   * @param materialToEncrypt The byte array of data to encrypt
   * @return A byte array of data encrypted using the symmetric key version
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public static byte[] encryptBytes(SymmetricKeyVersion keyVersion, byte[] materialToEncrypt)
      throws IllegalBlockSizeException, BadPaddingException {
    // encrypt the data
    byte[] encryptedData = keyVersion.getEncryptingCipher().doFinal(materialToEncrypt);

    // return the encrypted data
    return encryptedData;
  }

  /**
   * Decrypts a byte array using a symmetric key version
   *
   * @param keyVersion The symmetric key version to use to decrypt the data
   * @param materialToDecrypt The encrypted byte array of data to decrypt
   * @return A byte array of decrypted data
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public static byte[] decryptBytes(SymmetricKeyVersion keyVersion, byte[] materialToDecrypt)
      throws IllegalBlockSizeException, BadPaddingException {
    // decrypt the data
    byte[] decryptedData = keyVersion.getDecryptingCipher().doFinal(materialToDecrypt);

    // return the decrypted data
    return decryptedData;
  }

  /**
   * This method takes an input stream and encrypts it using a symmetric key version, giving an
   * encrypted output stream
   *
   * @param keyVersion The symmetric key version to use to encrypt the stream
   * @param in The input stream that we want to encrypt
   * @param out An output stream encrypted using the symmetric key version
   * @throws IOException
   */
  public static void encryptStream(SymmetricKeyVersion keyVersion, InputStream in, OutputStream out)
      throws IOException {
    // a byte array buffer to use when reading from the stream
    byte[] byteBuffer = new byte[1024];

    // initialize the output stream using the symmetric key version encrypting cipher
    out = new CipherOutputStream(out, keyVersion.getEncryptingCipher());

    // integer used to determine when we have read all of the input stream
    int i = 0;
    // read from the input stream into the byte array buffer
    while ((i = in.read(byteBuffer)) >= 0) {
      // now encrypt the data in the buffer using the cipher and write it to the output stream
      out.write(byteBuffer, 0, i);
    }
    // close the output stream to prevent resource leakage
    out.close();
  }

  /**
   * This method takes an encrypted input stream and decrypts it using a symmetric key version,
   * giving a decrypted output stream
   *
   * @param keyVersion The symmetric key version to use to decrypt the stream
   * @param in The encrypted input stream that we want to decrypt using the symmetric key version
   * @param out The decrypted output stream
   * @throws IOException
   */
  public static void decryptStream(SymmetricKeyVersion keyVersion, InputStream in, OutputStream out)
      throws IOException {
    // a byte array buffer to use when reading from the stream
    byte[] byteBuffer = new byte[1024];

    // initialize the input stream using the AES decrypting cipher
    in = new CipherInputStream(in, keyVersion.getDecryptingCipher());

    // integer used to determine when we have read all of the input stream
    int i = 0;
    // read from the input stream into the byte array buffer, decrypting the data using the
    // symmetric cipher
    while ((i = in.read(byteBuffer)) >= 0) {
      // write the data to the output stream
      out.write(byteBuffer, 0, i);
    }
    // close the output stream to prevent resource leakage
    out.close();
  }
}
