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

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.ChunkedMacVerification;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** AES-CMAC implementation of the ChunkedMac interface. */
@Immutable
public final class ChunkedAesCmacImpl implements ChunkedMac {
  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  @SuppressWarnings("Immutable") // We never change the key.
  private final AesCmacKey key;

  public ChunkedAesCmacImpl(AesCmacKey key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use AES-CMAC in FIPS-mode.");
    }
    this.key = key;
  }

  @Override
  public ChunkedMacComputation createComputation() throws GeneralSecurityException {
    return new ChunkedAesCmacComputation(key);
  }

  @Override
  public ChunkedMacVerification createVerification(final byte[] tag)
      throws GeneralSecurityException {
    if (tag.length < key.getOutputPrefix().size()) {
      throw new GeneralSecurityException("Tag too short");
    }
    if (!Arrays.equals(
        Arrays.copyOf(tag, key.getOutputPrefix().size()), key.getOutputPrefix().toByteArray())) {
      throw new GeneralSecurityException("Wrong tag prefix");
    }
    return new ChunkedAesCmacVerification(key, tag);
  }
}
