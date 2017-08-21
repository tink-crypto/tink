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

package com.google.crypto.tink.config;

import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.proto.RegistryConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import java.security.GeneralSecurityException;

/**
 * This class contains constants with configuration examples that can be used
 * for initializing the {@link Registry}.
 *
 * To register all key types provided in Tink release 1.0.0 one would use:
 *
 * <pre><code>
 * Config.register(TinkConfig.TINK_1_0_0);
 * </code></pre>
 */
public final class TinkConfig {
  public static final RegistryConfig TINK_1_0_0 = RegistryConfig.newBuilder()
      .mergeFrom(HybridConfig.TINK_1_0_0) // include AeadConfig.TINK_1_0_0 and MacConfig.TINK_1_0_0
      .mergeFrom(SignatureConfig.TINK_1_0_0)
      .setConfigName("TINK_1_0_0")
      .build();

  /**
   * Registers all catalogues with the {@link Registry}.
   */
  public static void init() throws GeneralSecurityException {
    HybridConfig.init(); // includes Aead and Mac
    SignatureConfig.init();
  }
}
