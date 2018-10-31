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

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

/**
 * Static methods for obtaining {@link PublicKeyVerify} instances.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(keysetHandle);
 * verifier.verify(signature, data);
 * }</pre>
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To verify a signature,
 * the primitive uses the prefix of the signature to efficiently select the right key in the set. If
 * there is no key associated with the prefix or if the keys associated with the prefix do not work,
 * the primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 *
 * @since 1.0.0
 */
public final class PublicKeyVerifyFactory {
  private static final Logger logger = Logger.getLogger(PublicKeyVerifyFactory.class.getName());

  /**
   * @return a PublicKeyVerify primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static PublicKeyVerify getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, /* keyManager= */ null);
  }

  /**
   * @return a PublicKeyVerify primitive from a {@code keysetHandle} and a custom {@code
   *     keyManager}.
   * @throws GeneralSecurityException
   */
  public static PublicKeyVerify getPrimitive(
      KeysetHandle keysetHandle, final KeyManager<PublicKeyVerify> keyManager)
      throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
    final PrimitiveSet<PublicKeyVerify> primitives =
        Registry.getPrimitives(keysetHandle, keyManager, PublicKeyVerify.class);
    return Registry.wrap(primitives);
  }
}
