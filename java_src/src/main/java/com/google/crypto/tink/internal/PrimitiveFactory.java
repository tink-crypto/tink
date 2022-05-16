// Copyright 2022 Google LLC
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

import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/** A PrimitiveFactory knows how to create primitives from a given key. */
public abstract class PrimitiveFactory<PrimitiveT, KeyProtoT extends MessageLite> {
  private final Class<PrimitiveT> clazz;

  public PrimitiveFactory(Class<PrimitiveT> clazz) {
    this.clazz = clazz;
  }

  /** Returns the class object corresponding to the generic parameter {@code PrimitiveT}. */
  final Class<PrimitiveT> getPrimitiveClass() {
    return clazz;
  }

  /**
   * Creates a new instance of {@code PrimitiveT}.
   *
   * <p>For primitives of type {@code Mac}, {@code Aead}, {@code PublicKeySign}, {@code
   * PublicKeyVerify}, {@code DeterministicAead}, {@code HybridEncrypt}, and {@code HybridDecrypt}
   * this should be a primitive which <b>ignores</b> the output prefix and assumes "RAW".
   */
  public abstract PrimitiveT getPrimitive(KeyProtoT key) throws GeneralSecurityException;
}
