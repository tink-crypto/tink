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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.Config;
import java.security.GeneralSecurityException;

/**
 * Static methods for registering with the {@link Registry} all instances of {@link
 * com.google.crypto.tink.PublicKeyVerify} key types supported in a particular release of Tink.
 *
 * <p>To register all PublicKeyVerify key types provided in Tink release 1.0.0 one can do:
 *
 * <pre>{@code
 * Config.register(PublicKeyVerifyConfig.TINK_1_0_0);
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of PublicKeyVerify, see {@link
 * PublicKeyVerifyFactory}.
 *
 * @deprecated use {@link Config} and {@link SignatureConfig}
 */
@Deprecated
public final class PublicKeyVerifyConfig {
  /**
   * Registers standard with the {@code Registry} all PublicKeyVerify key types released with the
   * latest version of Tink.
   *
   * <p>Deprecated-yet-still-supported key types are registered in so-called "no new key"-mode,
   * which allows for usage of existing keys forbids generation of new key material.
   *
   * @deprecated use {@link Config#register}
   */
  @Deprecated
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    Config.register(SignatureConfig.TINK_1_0_0);
  }

  private PublicKeyVerifyConfig() {}
}
