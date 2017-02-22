package com.google.cloud.crypto.tink;

import java.security.GeneralSecurityException;

/**
 * Interface for public key signing.
 * Implementations of this interface are secure against adaptive chosen-message attacks.
 * Signing data ensures authenticity and integrity of that data, but not its secrecy.
 */
public interface PublicKeySign {
  /**
   * Computes the signature for {@code data}.
   *
   * @returns the signature of {$code data}.
   */
  byte[] sign(byte[] data) throws GeneralSecurityException;
}
