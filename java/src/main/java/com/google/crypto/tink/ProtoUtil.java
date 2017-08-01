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

package com.google.crypto.tink;

import com.google.crypto.tink.proto.EcPointFormat;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.subtle.EcUtil;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

/**
 * Helper methods that deal with common protos.
 */
public final class ProtoUtil {
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
      case SHA256:
        return "HmacSha256";
      case SHA512:
        return "HmacSha512";
      default:
        throw new NoSuchAlgorithmException("hash unsupported for HMAC: " + hash);
    }
  }

  public static EcUtil.CurveTypeEnum toCurveTypeEnum(EllipticCurveType type)
      throws GeneralSecurityException {
    switch (type) {
      case NIST_P256:
        return EcUtil.CurveTypeEnum.NIST_P256;
      case NIST_P384:
        return EcUtil.CurveTypeEnum.NIST_P384;
      case NIST_P521:
        return EcUtil.CurveTypeEnum.NIST_P521;
      default:
        throw new GeneralSecurityException("unknown curve type: " + type);
    }
  }

  public static EcUtil.PointFormatEnum toPointFormatEnum(EcPointFormat format)
      throws GeneralSecurityException {
    switch (format) {
      case UNCOMPRESSED:
        return EcUtil.PointFormatEnum.UNCOMPRESSED;
      case COMPRESSED:
        return EcUtil.PointFormatEnum.COMPRESSED;
      default:
        throw new GeneralSecurityException("unknown point format: " + format);
    }
  }
}
