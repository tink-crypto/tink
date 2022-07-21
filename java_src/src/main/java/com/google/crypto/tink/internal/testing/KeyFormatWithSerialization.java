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

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.ProtoKeyFormatSerialization;

/**
 * Represents a {@link KeyFormat} together with a corresponding {@ProtoKeyFormatSerialization} for
 * testing.
 */
public class KeyFormatWithSerialization {
  /** Constructs a new KeyFormatWithSerialization. */
  public KeyFormatWithSerialization(
      Parameters parameters, ProtoKeyFormatSerialization serializedFormat) {
    this.parameters = parameters;
    this.serializedFormat = serializedFormat;
  }

  private final Parameters parameters;
  private final ProtoKeyFormatSerialization serializedFormat;

  /** Returns the {@link Parameters}. */
  public Parameters getParameters() {
    return parameters;
  }

  /** Returns the {@link ProtoKeyFormatSerialization}. */
  public ProtoKeyFormatSerialization getSerializedFormat() {
    return serializedFormat;
  }

  @Override
  public String toString() {
    return parameters.toString() + ", " + serializedFormat.toString();
  }
}
