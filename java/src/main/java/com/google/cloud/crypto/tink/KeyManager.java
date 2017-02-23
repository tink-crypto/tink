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
