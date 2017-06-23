// Copyright 2017 Google Inc.
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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EciesAeadHkdfParams;
import com.google.crypto.tink.subtle.EcUtil;
import com.google.crypto.tink.subtle.ProtoUtil;
import java.security.GeneralSecurityException;

class HybridUtil {
  /**
   * Validates EciesAeadHkdf params.
   *
   * @param params the EciesAeadHkdfParams protocol buffer.
   * @throws GeneralSecurityException iff it's invalid.
   */
  public static void validate(EciesAeadHkdfParams params) throws GeneralSecurityException {
    EcUtil.getCurveSpec(params.getKemParams().getCurveType());
    ProtoUtil.hashToHmacAlgorithmName(params.getKemParams().getHkdfHashType());
    if (params.getEcPointFormat() == EcPointFormat.UNKNOWN_FORMAT) {
      throw new GeneralSecurityException("unknown EC point format");
    }
    // Check that we can generate new keys from the DEM AEAD key format.
    Registry.INSTANCE.newKeyData(params.getDemParams().getAeadDem());
  }
}
