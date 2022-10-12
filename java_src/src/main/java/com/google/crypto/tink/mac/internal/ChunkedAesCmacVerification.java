// Copyright 2022 Google LLC
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

import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.crypto.tink.util.Bytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * An implementation of streaming CMAC verification. Uses ChunkedAesCmacComputation implementation
 * under the hood.
 */
final class ChunkedAesCmacVerification implements ChunkedMacVerification {
  private final Bytes tag;
  private final ChunkedAesCmacComputation aesCmacComputation;

  ChunkedAesCmacVerification(AesCmacKey key, byte[] tag)
      throws GeneralSecurityException {
    // Checks regarding tag and key sizes, as well as FIPS-compatibility, are performed by
    // ChunkedAesCmacImpl.
    aesCmacComputation = new ChunkedAesCmacComputation(key);
    this.tag = Bytes.copyFrom(tag);
  }

  @Override
  public void update(final ByteBuffer data) throws GeneralSecurityException {
    // No need to check state since the ChunkedAesCmacComputation already does this.
    aesCmacComputation.update(data);
  }

  @Override
  public void verifyMac() throws GeneralSecurityException {
    byte[] other = aesCmacComputation.computeMac();
    if (!tag.equals(Bytes.copyFrom(other))) {
      throw new GeneralSecurityException("invalid MAC");
    }
  }
}
