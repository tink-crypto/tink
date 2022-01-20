// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.SubtleUtil;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Hybrid Public Key Encryption (HPKE) context for either a sender or a recipient.
 *
 * <p>https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#name-creating-the-encryption-con
 */
@ThreadSafe
final class HpkeContext {
  private static final byte[] EMPTY_IKM = new byte[0];

  private final HpkeAead aead;
  private final BigInteger maxSequenceNumber;
  private final byte[] key;
  private final byte[] baseNonce;
  private final byte[] encapsulatedKey;

  @GuardedBy("this")
  private BigInteger sequenceNumber;

  private HpkeContext(
      byte[] encapsulatedKey,
      byte[] key,
      byte[] baseNonce,
      BigInteger maxSequenceNumber,
      HpkeAead aead) {
    this.encapsulatedKey = encapsulatedKey;
    this.key = key;
    this.baseNonce = baseNonce;
    this.sequenceNumber = BigInteger.ZERO;
    this.maxSequenceNumber = maxSequenceNumber;
    this.aead = aead;
  }

  /** Helper function factored out to facilitate unit testing. */
  static HpkeContext createContext(
      byte[] encapsulatedKey,
      byte[] sharedSecret,
      HpkeKem kem,
      HpkeKdf kdf,
      HpkeAead aead,
      byte[] info)
      throws GeneralSecurityException {
    byte[] suiteId = HpkeUtil.hpkeSuiteId(kem.getKemId(), kdf.getKdfId(), aead.getAeadId());
    byte[] pskIdHash = kdf.labeledExtract(HpkeUtil.EMPTY_SALT, EMPTY_IKM, "psk_id_hash", suiteId);
    byte[] infoHash = kdf.labeledExtract(HpkeUtil.EMPTY_SALT, info, "info_hash", suiteId);
    byte[] keyScheduleContext = Bytes.concat(HpkeUtil.BASE_MODE, pskIdHash, infoHash);
    byte[] secret = kdf.labeledExtract(sharedSecret, EMPTY_IKM, "secret", suiteId);

    byte[] key = kdf.labeledExpand(secret, keyScheduleContext, "key", suiteId, aead.getKeyLength());
    byte[] baseNonce =
        kdf.labeledExpand(secret, keyScheduleContext, "base_nonce", suiteId, aead.getNonceLength());
    BigInteger maxSeqNo = maxSequenceNumber(aead.getNonceLength());

    return new HpkeContext(encapsulatedKey, key, baseNonce, maxSeqNo, aead);
  }

  /**
   * Creates HPKE sender context according to KeySchedule() defined in
   * https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.1-9.
   *
   * @param recipientPublicKey recipient's public key (pkR)
   * @param kem key encapsulation mechanism primitive
   * @param kdf key derivation function primitive
   * @param aead authenticated encryption with associated data primitive
   * @param info application-specific information parameter to influence key generation
   */
  static HpkeContext createSenderContext(
      HpkePublicKey recipientPublicKey, HpkeKem kem, HpkeKdf kdf, HpkeAead aead, byte[] info)
      throws GeneralSecurityException {
    HpkeKemEncapOutput encapOutput =
        kem.encapsulate(recipientPublicKey.getPublicKey().toByteArray());
    byte[] encapsulatedKey = encapOutput.getEncapsulatedKey();
    byte[] sharedSecret = encapOutput.getSharedSecret();
    return createContext(encapsulatedKey, sharedSecret, kem, kdf, aead, info);
  }

  /**
   * Creates HPKE sender recipient context according to KeySchedule() defined in
   * https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.1-9.
   *
   * @param encapsulatedKey encapsulated key (enc)
   * @param recipientPrivateKey recipient's private key (skR)
   * @param kem key encapsulation mechanism primitive
   * @param kdf key derivation function primitive
   * @param aead authenticated encryption with associated data primitive
   * @param info application-specific information parameter to influence key generation
   */
  static HpkeContext createRecipientContext(
      byte[] encapsulatedKey,
      HpkePrivateKey recipientPrivateKey,
      HpkeKem kem,
      HpkeKdf kdf,
      HpkeAead aead,
      byte[] info)
      throws GeneralSecurityException {
    byte[] sharedSecret =
        kem.decapsulate(encapsulatedKey, recipientPrivateKey.getPrivateKey().toByteArray());
    return createContext(encapsulatedKey, sharedSecret, kem, kdf, aead, info);
  }

  private static BigInteger maxSequenceNumber(int nonceLength) {
    return BigInteger.ONE.shiftLeft(8 * nonceLength).subtract(BigInteger.ONE);
  }

  @GuardedBy("this")
  private void incrementSequenceNumber() throws GeneralSecurityException {
    if (sequenceNumber.compareTo(maxSequenceNumber) >= 0) {
      throw new GeneralSecurityException("message limit reached");
    }
    sequenceNumber = sequenceNumber.add(BigInteger.ONE);
  }

  /**
   * ComputeNonce() from
   * https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.2-11.
   */
  @GuardedBy("this")
  private byte[] computeNonce() throws GeneralSecurityException {
    return Bytes.xor(baseNonce, SubtleUtil.integer2Bytes(sequenceNumber, aead.getNonceLength()));
  }

  /** Returns the next nonce to use for seal/open. Also, increments the sequence number. */
  private synchronized byte[] computeNonceAndIncrementSequenceNumber()
      throws GeneralSecurityException {
    byte[] nonce = computeNonce();
    incrementSequenceNumber();
    return nonce;
  }

  byte[] getKey() {
    return key;
  }

  byte[] getBaseNonce() {
    return baseNonce;
  }

  byte[] getEncapsulatedKey() {
    return encapsulatedKey;
  }

  /**
   * Performs AEAD encryption of {@code plaintext} with {@code associatedData} according to
   * ContextS.Seal() defined in
   * https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.2-8.
   *
   * @return ciphertext
   */
  byte[] seal(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
    byte[] nonce = computeNonceAndIncrementSequenceNumber();
    return aead.seal(key, nonce, plaintext, associatedData);
  }

  /**
   * Performs AEAD decryption of {@code ciphertext} with {@code associatedData} according to
   * ContextR.Open() defined in
   * https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-5.2-10.
   *
   * @return plaintext
   */
  byte[] open(byte[] ciphertext, byte[] associatedData) throws GeneralSecurityException {
    byte[] nonce = computeNonceAndIncrementSequenceNumber();
    return aead.open(key, nonce, ciphertext, associatedData);
  }
}
