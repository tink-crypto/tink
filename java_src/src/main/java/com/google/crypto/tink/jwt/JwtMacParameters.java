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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.Parameters;

/** Represents a description of a {@link JwtMacKey} excluding the randomly chosen key material. */
public abstract class JwtMacParameters extends Parameters {
  /** If true, tokens without {@code "kid"} header are allowed when verifying a token. */
  public abstract boolean allowKidAbsent();
}
