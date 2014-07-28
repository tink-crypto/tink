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

import com.google.k2crypto.exceptions.BuilderException;
import com.google.k2crypto.exceptions.DecryptionException;
import com.google.k2crypto.exceptions.EncryptionException;
import com.google.k2crypto.keyversions.AESKeyVersion;
import com.google.k2crypto.keyversions.DSAPrivateKeyVersion;
import com.google.k2crypto.keyversions.HMACKeyVersion;
import com.google.k2crypto.keyversions.SymmetricKeyVersion;

/**
 * This class bundles together multiple keys to provide multiple operations for example we may want
 * AES and DSA to provide all four security services
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class CompoundKey {

  /**
   * Key used to perform HMAC operations
   */
  private Key hmacKey;

  /**
   * Key used to perform symmetric encryptions for example AES
   */
  private Key symmetricEncryptionKey;

  /**
   * Key used to perform digital signing for example DSA
   */
  private Key signingKey;

  /**
   * Initialize the HMAC key
   *
   * @throws BuilderException
   */
  public void initHmac() throws BuilderException {
    // Get an HMAC key version
    HMACKeyVersion hmacKeyVersion = HMACKeyVersion.generateHMAC(HMACKeyVersion.HMAC_SHA1);
    // now put it in a Key and set it as the HMAC key
    hmacKey = new Key(hmacKeyVersion);
  }

  /**
   * Initialize the symmetric encryption key
   *
   * @throws BuilderException
   */
  public void initSymEncryption() throws BuilderException {
    // Get an AES key version
    AESKeyVersion aesKeyVersion = new AESKeyVersion.Builder().keyVersionLengthInBytes(16).build();
    // now put it in a Key and set it as the symmetric encryption key
    symmetricEncryptionKey = new Key(aesKeyVersion);

    System.out.println(symmetricEncryptionKey.getPrimary().getId());
  }

  /**
   * Initialize the signing key
   *
   * @throws BuilderException
   */
  public void initSigning() throws BuilderException {
    // Get an DSA key version
    DSAPrivateKeyVersion dsaKeyVersion = new DSAPrivateKeyVersion.Builder().build();
    // now put it in a Key and set it as the digital signing key
    signingKey = new Key(dsaKeyVersion);

    System.out.println(signingKey.getPrimary().getId());
  }

  /**
   * Get digital signature using signing key
   *
   * @return The digital signature of the bytes generated using the signing key
   * @throws EncryptionException
   */
  public byte[] getSignature(byte[] dataToSign) throws EncryptionException {
    // check that the signing key has been initialized
    if (signingKey == null) {
      // if it has not then throw a new exception
      throw new EncryptionException("Signing key has not been initialized");
    }
    // use signing key to sign message and return to user
    return ((DSAPrivateKeyVersion) signingKey.getPrimary()).signData(dataToSign);
  }

  /**
   * Verify a digital signature using signing key
   *
   * @throws BuilderException
   * @throws EncryptionException
   */
  public boolean verifySignature(byte[] inputData, byte[] signature) throws EncryptionException,
      BuilderException {
    // check that the signing key has been initialized
    if (signingKey == null) {
      // if it has not then throw a new exception
      throw new EncryptionException("Signing key has not been initialized");
    }
    // verify the signature using the signing key
    return ((DSAPrivateKeyVersion) signingKey.getPrimary()).getPublic().verifySig(inputData,
        signature);
  }

  /**
   * Encrypt data using encryption key
   *
   * @param materialToEncrypt The data that we want to encrypt
   * @return The data encrypted using the encryption key
   * @throws EncryptionException
   */
  public byte[] encryptData(byte[] materialToEncrypt) throws EncryptionException {
    // check that the encryption key has been initialized
    if (this.symmetricEncryptionKey == null) {
      // if it has not then throw a new exception
      throw new EncryptionException("Encryption key has not been initialized");
    }
    // use the encryption key to encrypt the data
    return SymmetricEncryption.encryptBytes(
        (SymmetricKeyVersion) symmetricEncryptionKey.getPrimary(), materialToEncrypt);
  }

  /**
   * Decrypt data using encryption key
   *
   * @param materialToDecrypt The data that we want to decrypt
   * @return The material decrypted using the encryption key
   * @throws DecryptionException
   * @throws EncryptionException
   */
  public byte[] decryptData(byte[] materialToDecrypt) throws DecryptionException,
      EncryptionException {
    // check that the encryption key has been initialized
    if (symmetricEncryptionKey == null) {
      // if it has not then throw a new exception
      throw new EncryptionException("Encryption key has not been initialized");
    }
    // use the encryption key to decrypt the data
    return SymmetricEncryption.decryptBytes(
        (SymmetricKeyVersion) symmetricEncryptionKey.getPrimary(), materialToDecrypt);
  }

  /**
   * Get HMAC using hmac key
   *
   * @param message The message to use to get the HMAC
   * @return The HMAC generated using the HMAC key
   * @throws EncryptionException
   */
  public byte[] getHMAC(byte[] message) throws EncryptionException {
    // check that the HMAC key has been initialized
    if (hmacKey == null) {
      // if it has not then throw a new exception
      throw new EncryptionException("HMAC key has not been initialized");
    }
    // return the hmac generated using hmac key
    return ((HMACKeyVersion) hmacKey.getPrimary()).getRawHMAC(message);
  }

  /**
   * Verify that an HMAC against a message
   *
   * @param hmac The HMAC we want to verify
   * @param message The message to verify the HMAC against
   * @return True if and only if the hmac verifies against the message, false otherwise
   * @throws EncryptionException
   */
  public boolean verifyHMAC(byte[] hmac, byte[] message) throws EncryptionException {
    // check that the HMAC key has been initialized
    if (hmacKey == null) {
      // if it has not then throw a new exception
      throw new EncryptionException("HMAC key has not been initialized");
    }
    // verify hmac using hmac key
    return ((HMACKeyVersion) hmacKey.getPrimary()).verifyHMAC(hmac, message);
  }

  /**
   * Get the HMAC key
   *
   * @return The HMAC key
   */
  public Key getHmacKey() {
    return this.hmacKey;
  }

  /**
   * Get the signing key
   *
   * @return The signing key
   */
  public Key getSigningKey() {
    return this.signingKey;
  }

  /**
   * Get the HMAC key
   *
   * @return The HMAC key
   */
  public Key getEncryptionKey() {
    return this.symmetricEncryptionKey;
  }

  /**
   * Get a secure data blob using this compound key to secure the data
   *
   * @param inputData The data we want to secure
   * @return A SecureDataBlob representing the secured data
   * @throws EncryptionException
   */
  public SecureDataBlob getSecureData(byte[] inputData) throws EncryptionException {
    // secure data blob will store the secured data
    SecureDataBlob secureDataBlob = new SecureDataBlob();
    // secure the data using the compound key

    // do encryption if required
    if (this.getEncryptionKey() != null) {
      // get the encrypted data
      byte[] encryptedData = this.encryptData(inputData);
      // save the encrypted data in the secure data blob along with the ID used to do the encryption
      secureDataBlob.setEncryptedData(encryptedData, this.getEncryptionKey().getPrimary().getId());

      // do signing if required - using encrypted data
      if (this.getSigningKey() != null) {
        // also save key version ID used to to the signing
        secureDataBlob.setDigitalSignature(this.getSignature(encryptedData),
            this.getSigningKey().getPrimary().getId());
      }
      // do HMAC if required - using encrypted data
      if (this.getHmacKey() != null) {
        // save hmac and the key version ID of the hmac key version
        secureDataBlob.setHmac(this.getHMAC(encryptedData), this.getHmacKey().getPrimary().getId());
      }

      // else without encryption
    } else {
      // otherwise save the unencrypted data
      secureDataBlob.setUnencryptedData(inputData);

      // do signing if required - using plain unencrypted data
      if (this.getSigningKey() != null) {
        // also save key version ID used to to the signing
        secureDataBlob.setDigitalSignature(this.getSignature(inputData),
            this.getSigningKey().getPrimary().getId());
      }
      // do HMAC if required - using plain unencrypted data
      // save hmac and the key version ID of the hmac key version
      if (this.getHmacKey() != null) {
        secureDataBlob.setHmac(this.getHMAC(inputData), this.getHmacKey().getPrimary().getId());
      }
    }

    // return the secure data blob
    return secureDataBlob;
  }

  /**
   * Check the security properties of the secured data and return the raw data if the security
   * properties can be verified. Otherwise raise an exception
   *
   * @param secureDataBlob The secure data that we want to check
   * @return The original raw data
   * @throws K2Exception If the security properties of the secure data cannot be verified
   */
  public byte[] checkAndGetData(SecureDataBlob secureDataBlob) throws K2Exception {
    // check all the cryptographic properties of the data
    // if the data is encrypted
    if (secureDataBlob.isEncrypted) {
      // if the data is signed check the signature
      if (secureDataBlob.isSigned) {
        // check the digital signature
        if (!this.verifySignature(secureDataBlob.getEncryptedData(),
            secureDataBlob.getDigitalSignature())) {
          // if it does not verify, raise an exception
          throw new K2Exception("Digital signature did not verify");
        }
      }

      // if the data has an hmac, check it
      if (secureDataBlob.hasHmac) {
        // check the HMAC
        if (!this.verifyHMAC(secureDataBlob.getHmac(), secureDataBlob.getEncryptedData())) {
          // if it does not verify, raise an exception
          throw new K2Exception("HMAC did not verify");
        }
      }
      // decrypt data
      byte[] decryptedData = this.decryptData(secureDataBlob.getEncryptedData());
      // return decrypted data
      return decryptedData;

    } else {
      // data is unencrypted

      // if the data is signed check the signature
      if (secureDataBlob.isSigned) {
        // check the digital signature using UNENCRYPTED data
        if (!this.verifySignature(secureDataBlob.getUnencryptedData(),
            secureDataBlob.getDigitalSignature())) {
          // if it does not verify, raise an exception
          throw new K2Exception("Digital signature did not verify");
        }
      }

      // if the data has an hmac, check it
      if (secureDataBlob.hasHmac) {
        // check the HMAC using UNENCRYPTED data
        if (!this.verifyHMAC(secureDataBlob.getHmac(), secureDataBlob.getUnencryptedData())) {
          // if it does not verify, raise an exception
          throw new K2Exception("HMAC did not verify");
        }
      }

      // return the data
      return secureDataBlob.getUnencryptedData();
    }
  }

}
