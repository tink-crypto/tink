package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.protobuf.Any;
import java.security.GeneralSecurityException;

/**
 * KeyManager "understands" keys of specific key type(s):  it can generate keys
 * of the supported type(s) and create primitives for supported keys.
 * A key type is identified by the global name of the protocol buffer that holds
 * the corresponding key material, and is given by {@code typeUrl}-field
 * of {@code google.protobuf.Any}-protocol buffer.
 */
public interface KeyManager<Primitive> {
  /**
   * Constructs an instance of Primitive for the key given in {@code proto}.
   *
   * @returns the new constructed Primitive.
   * @throws GeneralSecurityException if the key given in {@code proto} is corrupted
   *         or not supported.
   */
  Primitive getPrimitive(Any proto) throws GeneralSecurityException;

  /**
   * Generates a new key according to specification in {@code keyFormat}.
   *
   * @returns the new generated key.
   * @throws GeneralSecurityException if the specified format is wrong or not supported.
   */
  Any newKey(KeyFormat keyFormat) throws GeneralSecurityException;

  /**
   * @returns true iff this KeyManager supports key type identified by {@code typeUrl}.
   */
  boolean doesSupport(String typeUrl);
}
