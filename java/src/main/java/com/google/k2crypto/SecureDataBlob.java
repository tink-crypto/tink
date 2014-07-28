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

import com.google.protobuf.ByteString;

/**
 * This class represents a blob of data secured according to NIST guidelines
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class SecureDataBlob {

  /**
   * Is the data encrypted
   */
  public boolean isEncrypted = false;

  /**
   * Is the data digitally signed
   */
  public boolean isSigned = false;

  /**
   * Does the data have an HMAC
   */
  public boolean hasHmac = false;

  /**
   * Digital signature
   */
  private byte[] digitalSignature = null;

  /**
   * Encrypted data
   */
  private byte[] encryptedData = null;

  /**
   * HMAC
   */
  private byte[] hmac = null;

  /**
   * Unencrypted data
   */
  private byte[] unencryptedData = null;

  /**
   * The ID of the HMAC KeyVersion
   */
  private ByteString hmacId;

  /**
   * The ID of the encryption KeyVersion
   */
  private ByteString encryptionId;

  /**
   * The ID of the signing KeyVersion
   */
  private ByteString signingId;

  /**
   * @return the hmacId
   */
  public ByteString getHmacId() {
    return hmacId;
  }

  /**
   * @return the encryptionId
   */
  public ByteString getEncryptionId() {
    return encryptionId;
  }

  /**
   * @return the signingId
   */
  public ByteString getSigningId() {
    return signingId;
  }


  /**
   * Set digital signature method
   *
   * @param signature
   */
  public void setDigitalSignature(byte[] signature, ByteString signingId) {
    this.digitalSignature = signature;
    this.isSigned = true;
    this.signingId = signingId;
  }

  /**
   * Set encrypted data method
   *
   * @param encryptedData
   */
  public void setEncryptedData(byte[] encryptedData, ByteString encryptionId) {
    this.encryptedData = encryptedData;
    this.isEncrypted = true;
    this.encryptionId = encryptionId;
  }

  /**
   * Set hmac method
   *
   * @param hmac
   */
  public void setHmac(byte[] hmac, ByteString hmacId) {
    this.hmac = hmac;
    this.hasHmac = true;
    this.hmacId = hmacId;
  }

  /**
   * Get the encrypted data
   *
   * @return the encrypted data
   */
  public byte[] getEncryptedData() {
    return this.encryptedData;
  }

  /**
   * Get the HMAC
   *
   * @return the HMAC
   */
  public byte[] getHmac() {
    return this.hmac;
  }

  /**
   * Get the unencrypted data
   *
   * @return the unencrypted data
   */
  public byte[] getUnencryptedData() {
    return this.unencryptedData;
  }


  /**
   * Get the digital signature
   *
   * @return the digital signature
   */
  public byte[] getDigitalSignature() {
    return this.digitalSignature;
  }

  /**
   * Set unencrypted data (use if we don't want encryption)
   *
   * @param inputData
   */
  public void setUnencryptedData(byte[] inputData) {
    this.unencryptedData = inputData;
  }


}
