package com.google.cloud.k2;

import java.security.GeneralSecurityException;

/**
 * The interface for authenticated encryption with additional authenticated
 * data. Implementations of this interface are secure against adaptive chosen
 * ciphertext attacks.
 */
public interface Aead {
  byte[] encrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException;
  byte[] decrypt(byte[] ciphertext, byte[] aad) throws GeneralSecurityException;
}
