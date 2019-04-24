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

import com.google.crypto.tink.annotations.Alpha;
import java.security.InvalidKeyException;

/**
 * XChaCha20Poly1305 AEAD construction, as described in
 * https://tools.ietf.org/html/draft-arciszewski-xchacha-01.
 */
@Alpha
public final class XChaCha20Poly1305 extends ChaCha20Poly1305Base {
  public XChaCha20Poly1305(final byte[] key) throws InvalidKeyException {
    super(key);
  }

  @Override
  ChaCha20Base newChaCha20Instance(final byte[] key, int initialCounter)
      throws InvalidKeyException {
    return new XChaCha20(key, initialCounter);
  }
}
