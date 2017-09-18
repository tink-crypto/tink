// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.subtle;

import static com.google.crypto.tink.subtle.Poly1305.MAC_TAG_SIZE_IN_BYTES;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.subtle.DjbCipher.ChaCha20Base;
import com.google.crypto.tink.subtle.DjbCipher.XSalsa20;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * DjbCipher (e.g., ChaCha20, XChaCha20, or XSalsa20) encryption/decryption with Poly1305 for AEAD
 * and X25519 for DH key exchange.
 *
 * <pre>
 * Example usage:
 * Alice's part:
 * <code>
 *   // receive Bob's publicKey.
 *   HybridEncrypt hybridEncrypt = NaClCryptoBox.hybridEncryptWithXSalsa20Poly1305(bobPublicKey);
 *   byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo \/* can be null *\/);
 *   // send ciphertext to Bob.
 * </code>
 * Bob's part:
 * <code>
 *   byte[] privateKey = NaClCryptoBox.generatePrivateKey();
 *   byte[] publicKey = NaClCryptoBox.getPublicKey(privateKey);
 *   // send publicKey to Alice.
 *   // receive ciphertext from Alice. (note that Alice's public key is prefixed to ciphertext)
 *   HybridDecrypt hybridDecrypt = NaClCryptoBox.hybridDecryptWithXSalsa20Poly1305(privateKey);
 *   byte[] plaintext = hybridDecrypt.decrypt(ciphertextFromAlice, contextInfo \/* can be null *\/);
 * </code>
 * </pre>
 */
@Alpha
public final class NaClCryptoBox {

  private static final byte[] EMPTY_AAD = new byte[0];

  private abstract static class X25519DjbCipherPoly1305Factory {
    abstract DjbCipherPoly1305 constructFromSymmetricKey(final byte[] sharedSecret);

    DjbCipherPoly1305 constructWithKem(final byte[] privateKey, final byte[] peerPublicKey) {
      return constructFromSymmetricKey(X25519.computeSharedSecret(privateKey, peerPublicKey));
    }
  }

  private static class XSalsa20Poly1305NaclFactory extends X25519DjbCipherPoly1305Factory {
    @Override
    public DjbCipherPoly1305 constructFromSymmetricKey(byte[] sharedSecret) {
      return DjbCipherPoly1305.constructXSalsa20Poly1305Nacl(XSalsa20.hSalsa20(sharedSecret));
    }
  }

  private static class ChaCha20Poly1305IetfFactory extends X25519DjbCipherPoly1305Factory {
    @Override
    public DjbCipherPoly1305 constructFromSymmetricKey(byte[] sharedSecret) {
      return DjbCipherPoly1305.constructChaCha20Poly1305Ietf(ChaCha20Base.hChaCha20(sharedSecret));
    }
  }

  private static class XChaCha20Poly1305IetfFactory extends X25519DjbCipherPoly1305Factory {
    @Override
    public DjbCipherPoly1305 constructFromSymmetricKey(byte[] sharedSecret) {
      return DjbCipherPoly1305.constructXChaCha20Poly1305Ietf(ChaCha20Base.hChaCha20(sharedSecret));
    }
  }

  /**
   * Returns a {@link HybridEncrypt} using {@link X25519} for DH key exchange, {@link XSalsa20} for
   * the symmetric key algorithm and {@link DjbCipherPoly1305} for AEAD.
   *
   * @param peerPublicKey public key of the peer user
   */
  public static HybridEncrypt hybridEncryptWithXSalsa20Poly1305(final byte[] peerPublicKey) {
    return new X25519DjbCipherPoly1305HybridEncrypt(
        peerPublicKey, new XSalsa20Poly1305NaclFactory());
  }

  /**
   * Returns a {@link HybridEncrypt} using {@link X25519} for DH key exchange, {@link
   * com.google.crypto.tink.subtle.DjbCipher.ChaCha20} for the symmetric key algorithm and {@link
   * DjbCipherPoly1305} for AEAD.
   *
   * @param peerPublicKey public key of the peer user
   */
  public static HybridEncrypt hybridEncryptWithChaCha20Poly1305(final byte[] peerPublicKey) {
    return new X25519DjbCipherPoly1305HybridEncrypt(
        peerPublicKey, new ChaCha20Poly1305IetfFactory());
  }

  /**
   * Returns a {@link HybridEncrypt} using {@link X25519} for DH key exchange, {@link
   * com.google.crypto.tink.subtle.DjbCipher.XChaCha20} for the symmetric key algorithm and {@link
   * DjbCipherPoly1305} for AEAD.
   *
   * @param peerPublicKey public key of the peer user
   */
  public static HybridEncrypt hybridEncryptWithXChaCha20Poly1305(final byte[] peerPublicKey) {
    return new X25519DjbCipherPoly1305HybridEncrypt(
        peerPublicKey, new XChaCha20Poly1305IetfFactory());
  }

  /**
   * Returns a {@link HybridDecrypt} using {@link X25519} for DH key exchange, {@link XSalsa20} for
   * the symmetric key algorithm and {@link DjbCipherPoly1305} for AEAD.
   *
   * @param privateKey private key for the current user
   */
  public static HybridDecrypt hybridDecryptWithXSalsa20Poly1305(final byte[] privateKey) {
    return new X25519DjbCipherPoly1305HybridDecrypt(privateKey, new XSalsa20Poly1305NaclFactory());
  }

  /**
   * Returns a {@link HybridDecrypt} using {@link X25519} for DH key exchange, {@link
   * com.google.crypto.tink.subtle.DjbCipher.ChaCha20} for the symmetric key algorithm and {@link
   * DjbCipherPoly1305} for AEAD.
   *
   * @param privateKey private key for the current user
   */
  public static HybridDecrypt hybridDecryptWithChaCha20Poly1305(final byte[] privateKey) {
    return new X25519DjbCipherPoly1305HybridDecrypt(privateKey, new ChaCha20Poly1305IetfFactory());
  }

  /**
   * Returns a {@link HybridDecrypt} using {@link X25519} for DH key exchange, {@link
   * com.google.crypto.tink.subtle.DjbCipher.XChaCha20} for the symmetric key algorithm and {@link
   * DjbCipherPoly1305} for AEAD.
   *
   * @param privateKey private key for the current user
   */
  public static HybridDecrypt hybridDecryptWithXChaCha20Poly1305(final byte[] privateKey) {
    return new X25519DjbCipherPoly1305HybridDecrypt(privateKey, new XChaCha20Poly1305IetfFactory());
  }

  /** Returns a random private key to be used on {@link X25519}. */
  public static byte[] generatePrivateKey() {
    return X25519.generatePrivateKey();
  }

  /** Returns the public key for the {@code privateKey} on {@link X25519}. */
  public static byte[] getPublicKey(final byte[] privateKey) {
    return X25519.publicFromPrivate(privateKey);
  }

  private static class X25519DjbCipherPoly1305HybridEncrypt implements HybridEncrypt {

    private final ImmutableByteArray ephemeralPublicKey;
    private final DjbCipherPoly1305 djbCipherPoly1305;

    private X25519DjbCipherPoly1305HybridEncrypt(
        final byte[] peerPublicKey, X25519DjbCipherPoly1305Factory factory) {
      final byte[] ephemeralPrivateKey = generatePrivateKey();
      ephemeralPublicKey = ImmutableByteArray.of(getPublicKey(ephemeralPrivateKey));
      this.djbCipherPoly1305 = factory.constructWithKem(ephemeralPrivateKey, peerPublicKey);
    }

    /**
     * Encrypts {@code plaintext}.
     *
     * @param plaintext data to encrypt.
     * @param contextInfo not used, can be null.
     * @return ciphertext in {@code publicKey || nonce || actual_ciphertext || tag} format
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] contextInfo) throws GeneralSecurityException {
      ByteBuffer output =
          ByteBuffer.allocate(
              Field25519.FIELD_LEN
                  + djbCipherPoly1305.nonceSizeInBytes()
                  + plaintext.length
                  + MAC_TAG_SIZE_IN_BYTES);
      output.put(ephemeralPublicKey.getBytes());
      djbCipherPoly1305.encrypt(output, plaintext, EMPTY_AAD);
      return output.array();
    }
  }

  private static class X25519DjbCipherPoly1305HybridDecrypt implements HybridDecrypt {

    private final ImmutableByteArray privateKey;
    private final X25519DjbCipherPoly1305Factory factory;

    private X25519DjbCipherPoly1305HybridDecrypt(
        final byte[] privateKey, X25519DjbCipherPoly1305Factory factory) {
      this.privateKey = ImmutableByteArray.of(privateKey);
      this.factory = factory;
    }

    /**
     * Decrypts {@code ciphertext}.
     *
     * @param ciphertext data to decrypt in {@code peerPublicKey || nonce || actual_ciphertext ||
     *     tag} format.
     * @param contextInfo not used, can be null.
     * @return plaintext data.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] contextInfo) throws GeneralSecurityException {
      ByteBuffer ciphertextBuf = ByteBuffer.wrap(ciphertext);
      final byte[] peerPublicKey = new byte[Field25519.FIELD_LEN];
      ciphertextBuf.get(peerPublicKey);
      return factory
          .constructWithKem(privateKey.getBytes(), peerPublicKey)
          .decrypt(ciphertextBuf, EMPTY_AAD);
    }
  }
}
