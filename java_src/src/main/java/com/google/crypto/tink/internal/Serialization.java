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

import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;

/**
 * Represents either a serialized {@code Key} or a serialized {@code Parameters} object.
 *
 * <p>Serialization objects are used within Tink to serialize keys, keysets, and key formats. For
 * each serialization method (e.g., for binary protobuf serialization), one subclass of this must be
 * defined.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
@Immutable
public interface Serialization {
  /**
   * Identifies which parsing method to use in the registry.
   *
   * <p>When registering a parsing function in the registry, one argument will be this object
   * identifier. When the registry is asked to parse a Serialization, the registry will then
   * dispatch it to the corresponding method.
   */
  public Bytes getObjectIdentifier();
}
