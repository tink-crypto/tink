// Copyright 2021 Google LLC
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
package com.google.crypto.tink.tinkkey.internal;

import com.google.crypto.tink.internal.KeyStatusTypeProtoConverter;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.TinkKey;

/**
 * Class used to expose the protected KeyHandle constructor to the rest of Tink. This class is for
 * Tink internal purposes only, and its public API is not guaranteed to be stable.
 */
public final class InternalKeyHandle extends KeyHandle {

  public InternalKeyHandle(
      TinkKey key, com.google.crypto.tink.proto.KeyStatusType status, int keyId) {
    super(key, KeyStatusTypeProtoConverter.fromProto(status), keyId);
  }
}
