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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.Mac;
import com.google.crypto.tink.prf.Prf;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/**
 * Class that provides the functionality expressed by the Mac primitive using a Prf implementation.
 */
@Immutable
public class PrfMac implements Mac {
  static final int MIN_TAG_SIZE_IN_BYTES = 10;

  private final Prf wrappedPrf;
  private final int tagSize;

  /** Wrap {@code wrappedPrf } in a Mac primitive with the specified {@code tagSize} */
  public PrfMac(Prf wrappedPrf, int tagSize) throws GeneralSecurityException {
    this.wrappedPrf = wrappedPrf;
    this.tagSize = tagSize;

    // The output length is restricted by the HMAC spec. Check that first.
    if (tagSize < MIN_TAG_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "tag size too small, need at least " + MIN_TAG_SIZE_IN_BYTES + " bytes");
    }

    // Some Prf implementations have restrictions on maximum tag length. These throw on compute().
    // Check for those restrictions on tag length here by doing a compute() pass.
    wrappedPrf.compute(new byte[0], tagSize);
  }

  @Override
  public byte[] computeMac(byte[] data) throws GeneralSecurityException {
    return wrappedPrf.compute(data, tagSize);
  }

  @Override
  public void verifyMac(byte[] mac, byte[] data) throws GeneralSecurityException {
    if (!Bytes.equal(computeMac(data), mac)) {
      throw new GeneralSecurityException("invalid MAC");
    }
  }
}
