package com.google.cloud.crypto.tink;

import java.security.GeneralSecurityException;

/**
 * Interface for MACs (Message Authentication Codes).
 * This interface should be used for authentication only, and not for other
 * purposes (for example, it should not be used to generate pseudorandom
 * bytes).
 */
public interface Mac {
  /**
   * Computes message authentication code (MAC) for {@code data}.
   *
   * @returns MAC value.
   */
  byte[] computeMac(byte[] data) throws GeneralSecurityException;

  /**
   * Verifies whether {@code mac} is a correct authentication code (MAC) for {@code data}.
   *
   * @returns true iff {@code mac} is a correct MAC for {@code data}.
   */
  boolean verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException;
}
