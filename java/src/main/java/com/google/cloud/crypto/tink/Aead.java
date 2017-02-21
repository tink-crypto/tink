package com.google.cloud.crypto.tink;

import java.security.GeneralSecurityException;
import java.util.concurrent.Future;

/**
 * The interface for authenticated encryption with additional authenticated data.
 * Implementations of this interface are secure against adaptive chosen ciphertext attacks.
 * Encryption with additional data ensures authenticity and integrity of that data,
 * but not its secrecy. (see RFC 5116, https://tools.ietf.org/html/rfc5116)
 */
public interface Aead {
  /**
   * Encrypts {@code plaintext} with {@code aad} as additional authenticated data.
   * The resulting ciphertext allows for checking authenticity and integrity
   * of additional data ({@code aad}), but does not guarantee its secrecy.
   *
   * @return resulting ciphertext.
   */
  byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException;

  /**
   * Decrypts {@code ciphertext} with {@code aad} as additional authenticated data.
   * The decryption verifies the authenticity and integrity of additional data ({@code aad}),
   * but there are no guarantees wrt. secrecy of that data.
   *
   * @return resulting plaintext.
   */
  byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException;

  /**
   * Encrypts {@code plaintext} with {@code aad} as additional authenticated data.
   * The resulting ciphertext allows for checking authenticity and integrity
   * of additional data ({@code aad}), but does not guarantee its secrecy.
   *
   * @return resulting ciphertext
   */
  Future<byte[]> asyncEncrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException;

  /**
   * Decrypts {@code ciphertext} with {@code aad} as additional authenticated data.
   * The decryption verifies the authenticity and integrity of additional data ({@code aad}),
   * but there are no guarantees wrt. secrecy of that data.
   *
   * @return resulting plaintext
   */
  Future<byte[]> asyncDecrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException;
}
