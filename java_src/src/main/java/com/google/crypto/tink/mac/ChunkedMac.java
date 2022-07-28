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

package com.google.crypto.tink.mac;

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * An interface representing Streaming MAC.
 * This interface should only be used for authentication. It should NOT
 * be used for other purposes; for instance, it is not guaranteed that this interface produces
 * pseudorandom bytes.
 */
@Immutable
public interface ChunkedMac {
  /**
   * Creates an instance of a single Chunked MAC computation.
   */
  ChunkedMacComputation createComputation() throws GeneralSecurityException;

  /**
   * Creates an instance of a single Chunked MAC verification.
   */
  ChunkedMacVerification createVerification(final byte[] tag) throws GeneralSecurityException;
}
