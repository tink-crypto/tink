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

package com.google.tink1to2;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.errorprone.refaster.annotation.AfterTemplate;
import com.google.errorprone.refaster.annotation.BeforeTemplate;
import java.security.GeneralSecurityException;

final class KeysetHandleChanges {
  class CleanupKeysetHandleReaderNoSecret {
    @BeforeTemplate
    public KeysetHandle beforeTemplate(byte[] b) throws GeneralSecurityException {
      return KeysetHandle.readNoSecret(b);
    }

    @AfterTemplate
    public KeysetHandle afterTemplate(byte[] b) throws GeneralSecurityException {
      return TinkProtoKeysetFormat.parseKeysetWithoutSecret(b);
    }
  }
}
