// Copyright 2017 Google Inc.
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

package com.google.cloud.crypto.tink.subtle;

/**
 * Helper methods.
 */
public class Util {
  /**
   * Best effort fix-timing array comparison.
   * @returns true if two arrays are equal.
   */
  public static final boolean arrayEquals(byte[] x, byte[] y) {
    if (x == null || y == null) {
      return false;
    }
    if (x.length != y.length) {
      return false;
    }
    int res = 0;
    for (int i = 0; i < x.length; i++) {
      res |= x[i] ^ y[i];
    }
    return res == 0;
  }
}
