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

package com.google.tinkuser;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KeysetReader;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Example user code */
public final class TinkUser {
  public Aead useReadNoSecret(byte[] b) throws GeneralSecurityException {
    return KeysetHandle.readNoSecret(b).getPrimitive(Aead.class);
  }
  public Aead useBinaryReader(byte[] b) throws GeneralSecurityException, IOException {
    return KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(b)).getPrimitive(Aead.class);
  }
  public Aead useAnyReader(KeysetReader r) throws GeneralSecurityException, IOException {
    return KeysetHandle.readNoSecret(r).getPrimitive(Aead.class);
  }
}
