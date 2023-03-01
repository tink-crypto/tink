// Copyright 2023 Google LLC
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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.Key;
import javax.annotation.Nullable;

/** Represents functions to encrypt and decrypt data using a StreamingAead. */
public abstract class StreamingAeadKey extends Key {
  @Override
  @Nullable
  public final Integer getIdRequirementOrNull() {
    return null;
  }

  @Override
  public abstract StreamingAeadParameters getParameters();
}
