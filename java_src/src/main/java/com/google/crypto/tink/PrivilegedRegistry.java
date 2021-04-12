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

package com.google.crypto.tink;

import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Privileged access to the Registry.
 *
 * <p>Access is granted on the BUILD.bazel-file level. This is internal and should not be used
 * externally.
 */
public class PrivilegedRegistry {

  private PrivilegedRegistry() {}

  /**
   * Method to derive a key, using the given {@param keyTemplate}, with the randomness as provided
   * by the second argument.
   *
   * <p>This method is on purpose not in the public interface. Calling it twice using different key
   * templates and the same randomness can completely destroy any security in a system, so we
   * prevent this by making it accessible only to safe call sites.
   *
   * <p>This functions ignores {@code keyTemplate.getOutputPrefix()}.
   */
  public static KeyData deriveKey(KeyTemplate keyTemplate, InputStream randomStream)
      throws GeneralSecurityException {
    return Registry.deriveKey(keyTemplate, randomStream);
  }

  /**
   * Returns the key proto in the keyData if a corresponding key type manager was registered.
   * Returns null if the key type was registered with a {@link KeyManager} (and not a {@link
   * KeyTypeManager}).
   */
  public static MessageLite parseKeyData(KeyData keyData)
      throws GeneralSecurityException, InvalidProtocolBufferException {
    return Registry.parseKeyData(keyData);
  }

}
