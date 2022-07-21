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
import com.google.crypto.tink.internal.ProtoParametersSerialization;

/**
 * Represents a {@link Parameters} object together with a corresponding {@link
 * ProtoParametersSerialization} for testing.
 */
public class ParametersWithSerialization {
  /** Constructs a new ParametersWithSerialization. */
  public ParametersWithSerialization(
      Parameters parameters, ProtoParametersSerialization serializedParameters) {
    this.parameters = parameters;
    this.serializedParameters = serializedParameters;
  }

  private final Parameters parameters;
  private final ProtoParametersSerialization serializedParameters;

  /** Returns the {@link Parameters}. */
  public Parameters getParameters() {
    return parameters;
  }

  /** Returns the {@link ProtoParametersSerialization}. */
  public ProtoParametersSerialization getSerializedParameters() {
    return serializedParameters;
  }

  @Override
  public String toString() {
    return parameters.toString() + ", " + serializedParameters.toString();
  }
}
