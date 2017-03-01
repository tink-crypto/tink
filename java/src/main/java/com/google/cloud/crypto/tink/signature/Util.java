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

package com.google.cloud.crypto.tink.signature;

import com.google.cloud.crypto.tink.CommonProto.EllipticCurveType;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.EcdsaProto.EcdsaParams;
import com.google.cloud.crypto.tink.subtle.EcUtil;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECParameterSpec;

final class Util {
  /**
   * Returns the Ecdsa algorithm name corresponding to a hash type.
   *
   * @param hash the hash type
   * @return the JCE's Ecdsa algorithm name for the hash.
   */
  public static String hashToEcdsaAlgorithmName(HashType hash) throws NoSuchAlgorithmException {
    switch(hash) {
      case SHA256:
        return "SHA256WithECDSA";
      case SHA512:
        return "SHA512WithECDSA";
      default:
        throw new NoSuchAlgorithmException("Hash unsupported for signature: " + hash);
    }
  }

  /**
   * Returns the ECParameterSpec for a named curve.
   *
   * @param curve the curve type
   * @return the ECParameterSpec for the curve.
   */
  public static ECParameterSpec getCurveSpec(EllipticCurveType curve)
      throws NoSuchAlgorithmException {
        switch(curve) {
          case NIST_P256:
            return EcUtil.getNistP256Params();
          case NIST_P384:
            return EcUtil.getNistP384Params();
          case NIST_P521:
            return EcUtil.getNistP521Params();
          default:
            throw new NoSuchAlgorithmException("Curve not implemented:" + curve);
        }
      }


  /**
   * Validates Ecdsa's parameters. The hash's strength must not be weaker than the curve's strength.
   *
   * @param params the Ecdsa's parameters protocol buffer.
   * @return true iff it's valid.
   */
  public static boolean validateEcdsaParams(EcdsaParams params) {
    HashType hash = params.getHashType();
    EllipticCurveType curve = params.getCurve();
    switch(curve) {
      case NIST_P256:
        // Using SHA512 for curve P256 is fine. However, only the 256 leftmost bits of the hash is
        // used in signature computation. Therefore, we don't allow it here to prevent security's
        // illusion.
        return hash == HashType.SHA256;
      case NIST_P384:
        /* fall through */
      case NIST_P521:
        return hash == HashType.SHA512;
      default:
        return false;
    }
  }
}
