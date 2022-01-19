// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.subtle;

/** Enums used by classes in subtle. */
public final class Enums {
  /** Hash type. */
  public enum HashType {
    SHA1, // Using SHA1 for digital signature is deprecated but HMAC-SHA1 is fine.
    SHA224,
    SHA256,
    SHA384,
    SHA512,
  };

  private Enums() {}
}
