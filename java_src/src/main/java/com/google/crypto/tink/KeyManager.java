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

package com.google.crypto.tink;

import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * A KeyManager "understands" keys of a specific key type: it can generate keys of the supported
 * type and create primitives for supported keys.
 *
 * <p>A key type is identified by the global name of the protocol buffer that holds the
 * corresponding key material, and is given by {@code typeUrl}-field of {@link KeyData}-protocol
 * buffer.
 *
 * <p>The template parameter {@code P} denotes the primitive corresponding to the keys handled by
 * this manager.
 *
 * @since 1.0.0
 */
public interface KeyManager<P> {
  // APIs for primitive development

  /**
   * Constructs an instance of P for the key given in {@code serializedKey}, which must be a
   * serialized key protocol buffer handled by this manager.
   *
   * <p>For primitives of type {@code Mac}, {@code Aead}, {@code PublicKeySign}, {@code
   * PublicKeyVerify}, {@code DeterministicAead}, {@code HybridEncrypt}, and {@code HybridDecrypt}
   * this should be a primitive which <b>ignores</b> the output prefix and assumes "RAW".
   *
   * @return the new constructed P
   * @throws GeneralSecurityException if the key given in {@code serializedKey} is corrupted or not
   *     supported
   */
  P getPrimitive(ByteString serializedKey) throws GeneralSecurityException;

  /**
   * Constructs an instance of P for the key given in {@code key}.
   *
   * <p>For primitives of type {@code Mac}, {@code Aead}, {@code PublicKeySign}, {@code
   * PublicKeyVerify}, {@code DeterministicAead}, {@code HybridEncrypt}, and {@code HybridDecrypt}
   * this should be a primitive which <b>ignores</b> the output prefix and assumes "RAW".
   *
   * @return the new constructed P
   * @throws GeneralSecurityException if the key given in {@code key} is corrupted or not supported
   */
  P getPrimitive(MessageLite key) throws GeneralSecurityException;

  /**
   * Generates a new key according to specification in {@code serializedKeyFormat}, which must be a
   * serialized key format protocol buffer handled by this manager.
   *
   * @return the new generated key
   * @throws GeneralSecurityException if the specified format is wrong or not supported
   */
  MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException;

  /**
   * Generates a new key according to specification in {@code keyFormat}.
   *
   * @return the new generated key
   * @throws GeneralSecurityException if the specified format is wrong or not supported
   */
  MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException;

  /** @return true iff this KeyManager supports key type identified by {@code typeUrl}. */
  boolean doesSupport(String typeUrl);

  /** @return the type URL that identifies the key type of keys managed by this KeyManager. */
  String getKeyType();

  /** @return the version number of this KeyManager. */
  int getVersion();

  /**
   * Returns the primitive class object of the P. Should be implemented as {@code return P.class;}
   * when implementing a key manager for primitive {$code P}.
   *
   * @return {@code P.class}
   */
  Class<P> getPrimitiveClass();

  // APIs for Key Management

  /**
   * Generates a new {@code KeyData} according to specification in {@code serializedkeyFormat}.
   *
   * <p>This should be used solely by {@link KeysetManager}.
   *
   * @return the new generated key
   * @throws GeneralSecurityException if the specified format is wrong or not supported
   */
  KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException;
}
