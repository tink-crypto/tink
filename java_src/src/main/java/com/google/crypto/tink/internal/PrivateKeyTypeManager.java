// Copyright 2020 Google LLC
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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.annotations.Alpha;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/**
 * A PrivateKeyManager is like an {@link KeyTypeManager}, but additionally has a method to create a
 * public key.
 */
@Alpha
public abstract class PrivateKeyTypeManager<
        KeyProtoT extends MessageLite, PublicKeyProtoT extends MessageLite>
    extends KeyTypeManager<KeyProtoT> {

  @SafeVarargs // Safe because super() is marked as safe.
  protected PrivateKeyTypeManager(
      Class<KeyProtoT> clazz,
      Class<PublicKeyProtoT> publicKeyClazz,
      KeyTypeManager.PrimitiveFactory<?, KeyProtoT>... factories) {
    super(clazz, factories);
    this.publicKeyClazz = publicKeyClazz;
  }

  private final Class<PublicKeyProtoT> publicKeyClazz;

  /** Returns the class corresponding to the public key protobuffer. */
  public final Class<PublicKeyProtoT> getPublicKeyClass() {
    return publicKeyClazz;
  }

  /** Creates a public key from the given private key. */
  public abstract PublicKeyProtoT getPublicKey(KeyProtoT keyProto)
      throws GeneralSecurityException;
}
