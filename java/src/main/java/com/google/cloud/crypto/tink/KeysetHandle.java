package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.Keyset;

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure
 * of actual protocol buffers that hold sensitive key material.
 *
 * NOTE: this is an initial definition of this interface, which needs more work.
 *   It should probably be an abstract class which does not provide public access
 *   to the actual key material.
 */
public interface KeysetHandle {
  /**
   * @returns source of the key material of this keyset (e.g. Keystore, Cloud KMS).
   */
  byte[] getSource();

  /**
   * @returns the actual keyset data.
   */
  Keyset getKeyset();
}
