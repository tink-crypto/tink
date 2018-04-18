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

import com.google.crypto.tink.daead.DeterministicAeadConfig;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.proto.RegistryConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of all key types supported in a particular release of Tink.
 *
 * <p>To register all key types provided in Tink release 1.1.0 one can do:
 *
 * <pre>{@code
 * Config.register(TinkConfig.TINK_1_1_0);
 * }</pre>
 *
 * @since 1.0.0
 */
public final class TinkConfig {
  public static final RegistryConfig TINK_1_0_0 =
      RegistryConfig.newBuilder()
          .mergeFrom(
              HybridConfig.TINK_1_0_0) // include AeadConfig.TINK_1_0_0 and MacConfig.TINK_1_0_0
          .mergeFrom(SignatureConfig.TINK_1_0_0)
          .setConfigName("TINK_1_0_0")
          .build();

  /** @since 1.1.0 */
  public static final RegistryConfig TINK_1_1_0 =
      RegistryConfig.newBuilder()
          .mergeFrom(
              HybridConfig.TINK_1_1_0) // include AeadConfig.TINK_1_0_0 and MacConfig.TINK_1_0_0
          .mergeFrom(SignatureConfig.TINK_1_1_0)
          .mergeFrom(DeterministicAeadConfig.TINK_1_1_0)
          .mergeFrom(StreamingAeadConfig.TINK_1_1_0)
          .setConfigName("TINK_1_1_0")
          .build();

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.Catalogue} needed to handle all key types supported in Tink.
   */
  public static void init() throws GeneralSecurityException {
    DeterministicAeadConfig.init();
    HybridConfig.init(); // includes Aead and Mac
    SignatureConfig.init();
  }
}
