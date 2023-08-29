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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.testing.TestUtil;
import org.conscrypt.Conscrypt;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class RandomWithoutInstallingConscryptTest {

  @Test
  public void randBytes_usesConscrypt() throws Exception {
    assertThat(Random.randBytes(10)).hasLength(10);

    Random.validateUsesConscrypt();

    if (!TestUtil.isAndroid()) {
      // Make a call to Conscrypt to make sure it is present. But don't install it.
      Conscrypt.checkAvailability();
    }
  }
}
