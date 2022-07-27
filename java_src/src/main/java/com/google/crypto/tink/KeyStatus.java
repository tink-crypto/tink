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

package com.google.crypto.tink;

import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.Immutable;

/**
 * Represents the status of a key in a keyset.
 *
 * <p>Note that the status of a key is not part of the key itself, it is metadata about the key
 * that is for example stored in a keyset.
 */
@Immutable
@Alpha
public final class KeyStatus {
  public static final KeyStatus ENABLED = new KeyStatus("ENABLED");
  public static final KeyStatus DISABLED = new KeyStatus("DISABLED");
  public static final KeyStatus DESTROYED = new KeyStatus("DESTROYED");

  private final String name;

  private KeyStatus(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return name;
  }
}
