// Copyright 2020 Google LLC
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

package com.google.crypto.tink.keyderivation;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeysetDeriverWrapper. */
@RunWith(JUnit4.class)
public class KeysetDeriverWrapperTest {
  /*
   * There isn't much to test here. We never allowed registering the key manager separately, so
   * KeysetDeriverWrapper.register really should just not throw in case one registers key derivation
   * normally.
   */
  @Test
  public void test_registerDoesNotThrow() throws Exception {
    KeyDerivationConfig.register();
    KeysetDeriverWrapper.register();
  }
}
