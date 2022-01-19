// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.testing;

import com.google.crypto.tink.hybrid.internal.HpkeUtil;
import com.google.crypto.tink.subtle.Hex;
import java.util.Arrays;
import java.util.Objects;

/** Helper class for identifying different test cases. */
public final class HpkeTestId {
  public final byte[] mode;
  public final byte[] kemId;
  public final byte[] kdfId;
  public final byte[] aeadId;

  public HpkeTestId(byte[] mode, byte[] kemId, byte[] kdfId, byte[] aeadId) {
    this.mode = mode;
    this.kemId = kemId;
    this.kdfId = kdfId;
    this.aeadId = aeadId;
  }

  public HpkeTestId(int mode, int kemId, int kdfId, int aeadId) {
    this.mode = HpkeUtil.intToByteArray(1, mode);
    this.kemId = HpkeUtil.intToByteArray(2, kemId);
    this.kdfId = HpkeUtil.intToByteArray(2, kdfId);
    this.aeadId = HpkeUtil.intToByteArray(2, aeadId);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof HpkeTestId)) {
      return false;
    }
    HpkeTestId testId = (HpkeTestId) obj;
    return Arrays.equals(this.mode, testId.mode)
        && Arrays.equals(this.kemId, testId.kemId)
        && Arrays.equals(this.kdfId, testId.kdfId)
        && Arrays.equals(this.aeadId, testId.aeadId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        Arrays.hashCode(mode),
        Arrays.hashCode(kemId),
        Arrays.hashCode(kdfId),
        Arrays.hashCode(aeadId));
  }

  @Override
  public String toString() {
    return String.format(
        "mode=0x%s, kem_id=0x%s, kdf_id=0x%s, aead_id=0x%s",
        Hex.encode(mode), Hex.encode(kemId), Hex.encode(kdfId), Hex.encode(aeadId));
  }
}
