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
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.subtle.EllipticCurves;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

final class HybridUtil {
  /**
   * Validates EciesAeadHkdf params.
   *
   * @param params the EciesAeadHkdfParams protocol buffer.
   * @throws GeneralSecurityException iff it's invalid.
   */
  public static void validate(EciesAeadHkdfParams params) throws GeneralSecurityException {
    EllipticCurves.getCurveSpec(HybridUtil.toCurveType(params.getKemParams().getCurveType()));
    HybridUtil.toHmacAlgo(params.getKemParams().getHkdfHashType());
    if (params.getEcPointFormat() == EcPointFormat.UNKNOWN_FORMAT) {
      throw new GeneralSecurityException("unknown EC point format");
    }
    // Check that we can generate new keys from the DEM AEAD key format.
    Registry.newKeyData(params.getDemParams().getAeadDem());
  }

  /**
   * Returns the HMAC algorithm name corresponding to a hash type.
   *
   * @param hash the hash type
   * @return the JCE's HMAC algorithm name for the hash.
   */
  public static String toHmacAlgo(HashType hash) throws NoSuchAlgorithmException {
    switch (hash) {
      case SHA1:
        return "HmacSha1";
      case SHA224:
        return "HmacSha224";
      case SHA256:
        return "HmacSha256";
      case SHA384:
        return "HmacSha384";
      case SHA512:
        return "HmacSha512";
      default:
        throw new NoSuchAlgorithmException("hash unsupported for HMAC: " + hash);
    }
  }

  /** Converts protobuf enum {@code EllipticCurveType} to raw Java enum {code CurveType}. */
  public static EllipticCurves.CurveType toCurveType(EllipticCurveType type)
      throws GeneralSecurityException {
    switch (type) {
      case NIST_P256:
        return EllipticCurves.CurveType.NIST_P256;
      case NIST_P384:
        return EllipticCurves.CurveType.NIST_P384;
      case NIST_P521:
        return EllipticCurves.CurveType.NIST_P521;
      default:
        throw new GeneralSecurityException("unknown curve type: " + type);
    }
  }

  /** Converts protobuf enum {@code EcPointFormat} to raw Java enum {code PointFormatType}. */
  public static EllipticCurves.PointFormatType toPointFormatType(EcPointFormat format)
      throws GeneralSecurityException {
    switch (format) {
      case UNCOMPRESSED:
        return EllipticCurves.PointFormatType.UNCOMPRESSED;
      case DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
        return EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED;
      case COMPRESSED:
        return EllipticCurves.PointFormatType.COMPRESSED;
      default:
        throw new GeneralSecurityException("unknown point format: " + format);
    }
  }

  private HybridUtil() {}
}
