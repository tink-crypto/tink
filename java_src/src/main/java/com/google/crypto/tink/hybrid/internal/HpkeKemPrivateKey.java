// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;

/** Interface for private keys for Key Encapsulation Mechanism (KEM) */
@Immutable
public interface HpkeKemPrivateKey {
  /** Gets the serialized KEM private key to perform decapsulation. */
  Bytes getSerializedPrivate();

  /**
   * Gets the serialized KEM public key corresponding to the private key to perform decapsulation.
   */
  Bytes getSerializedPublic();
}
