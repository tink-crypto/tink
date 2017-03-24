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

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * KeyManager "understands" keys of a specific key type: it can generate keys
 * of the supported type and create primitives for supported keys.
 * A key type is identified by the global name of the protocol buffer that holds
 * the corresponding key material, and is given by {@code typeUrl}-field
 * of {@code KeyData}-protocol buffer.
 */
public interface KeyManager<P, K extends MessageLite, F extends MessageLite> {
  // APIs for primitive development

  /**
   * Constructs an instance of P for the key given in {@code serialized},
   * which must be a serialized {@code K}-proto.
   *
   * @return the new constructed P.
   * @throws GeneralSecurityException if the key given in {@code serialized} is corrupted
   *         or not supported.
   */
  P getPrimitive(ByteString serialized) throws GeneralSecurityException;

  /**
   * Constructs an instance of P for the key given in {@code proto}.
   *
   * @return the new constructed P.
   * @throws GeneralSecurityException if the key given in {@code proto} is corrupted
   *         or not supported.
   */
  P getPrimitive(K proto) throws GeneralSecurityException;

  /**
   * Generates a new key according to specification in {@code serialized},
   * which must be a serialized {@code F}-proto.
   *
   * @return the new generated key.
   * @throws GeneralSecurityException if the specified format is wrong or not supported.
   */
  K newKey(ByteString serialized) throws GeneralSecurityException;

  /**
   * Generates a new key according to specification in {@code proto}.
   *
   * @return the new generated key.
   * @throws GeneralSecurityException if the specified format is wrong or not supported.
   */
  K newKey(F proto) throws GeneralSecurityException;

  /**
   * @return true iff this KeyManager supports key type identified by {@code typeUrl}.
   */
  boolean doesSupport(String typeUrl);

  // APIs for Key Management

  /**
   * Generates a new {@code KeyData} according to specification in {@code serialized}.
   * This should be used solely by the key management API.
   *
   * @return the new generated key.
   * @throws GeneralSecurityException if the specified format is wrong or not supported.
   */
  KeyData newKeyData(ByteString serialized) throws GeneralSecurityException;
}
