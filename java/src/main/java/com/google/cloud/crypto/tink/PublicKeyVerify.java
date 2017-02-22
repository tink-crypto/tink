package com.google.cloud.crypto.tink;

import java.security.GeneralSecurityException;

/**
 * Interface for verification of public key signature.
 * Implementations of this interface are secure against adaptive chosen-message attacks.
 * Signing data ensures authenticity and integrity of that data, but not its secrecy.
 */
public interface PublicKeyVerify {
  /**
   * Verifies whether {@code signature} is a valid signature for {@code data}.
   *
   * @returns true iff {@code signature} is a valid signature for {@code data}.
   */
  boolean verify(byte[] signature, byte[] data) throws GeneralSecurityException;
}
