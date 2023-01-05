// Copyright 2022 Google Inc.
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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.util.Bytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * An implementation of streaming HMAC verification. Uses ChunkedHmacComputation implementation
 * under the hood. Not thread-safe, thread safety must be ensured by the caller if objects of this
 * class are accessed concurrently.
 */
final class ChunkedHmacVerification implements ChunkedMacVerification {
  private final Bytes tag;
  private final ChunkedHmacComputation hmacComputation;

  ChunkedHmacVerification(HmacKey key, byte[] tag) throws GeneralSecurityException {
    hmacComputation = new ChunkedHmacComputation(key);
    this.tag = Bytes.copyFrom(tag);
  }

  @Override
  public void update(ByteBuffer data) {
    // No need to check state since the ChunkedHmacComputation already does this.
    hmacComputation.update(data);
  }

  @Override
  public void verifyMac() throws GeneralSecurityException {
    byte[] other = hmacComputation.computeMac();
    if (!tag.equals(Bytes.copyFrom(other))) {
      throw new GeneralSecurityException("invalid MAC");
    }
  }
}
