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

package com.google.crypto.tink.internal.testing;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.ProtoKeySerialization;

/** Represents a {@link Key} together with a corresponding {@ProtoKeySerialization} for testing. */
public final class KeyWithSerialization {
  /** Constructs a new KeyWithSerialization. */
  public KeyWithSerialization(Key key, ProtoKeySerialization serializedKey) {
    this.key = key;
    this.serializedKey = serializedKey;
  }

  private final Key key;
  private final ProtoKeySerialization serializedKey;

  /** Returns the {@link Key}. */
  public Key getKey() {
    return key;
  }

  /** Returns the {@link ProtoKeySerialization}. */
  public ProtoKeySerialization getSerialization() {
    return serializedKey;
  }
}
