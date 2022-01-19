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

package com.google.crypto.tink.signature.internal;

import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Enums;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

/** Utility functions to convert to and from signature-related proto. */
public final class SigUtil {
  static final String INVALID_PARAMS = "Invalid ECDSA parameters";

  /**
   * Validates Ecdsa's parameters. The hash's strength must not be weaker than the curve's strength.
   *
   * @param params the Ecdsa's parameters protocol buffer.
   * @throws GeneralSecurityException iff it's invalid.
   */
  public static void validateEcdsaParams(EcdsaParams params) throws GeneralSecurityException {
    EcdsaSignatureEncoding encoding = params.getEncoding();
    HashType hash = params.getHashType();
    EllipticCurveType curve = params.getCurve();
    switch (encoding) {
      case DER: // fall through
      case IEEE_P1363:
        break;
      default:
        throw new GeneralSecurityException("unsupported signature encoding");
    }
    switch (curve) {
      case NIST_P256:
        // Using SHA512 for curve P256 is fine. However, only the 256 leftmost bits of the hash is
        // used in signature computation. Therefore, we don't allow it here to prevent security
        // illusion.
        if (hash != HashType.SHA256) {
          throw new GeneralSecurityException(INVALID_PARAMS);
        }
        break;
      case NIST_P384:
        if (hash != HashType.SHA384 && hash != HashType.SHA512) {
          throw new GeneralSecurityException(INVALID_PARAMS);
        }
        break;
      case NIST_P521:
        if (hash != HashType.SHA512) {
          throw new GeneralSecurityException(INVALID_PARAMS);
        }
        break;
      default:
        throw new GeneralSecurityException(INVALID_PARAMS);
    }
  }

  /**
   * Validates RsaSsaPkcs1's parameters. As SHA1 is unsafe, we will only support SHA256 and SHA512
   * for digital signature.
   *
   * @param params the RsaSsaPkcs1Params protocol buffer.
   * @throws GeneralSecurityException iff it's invalid.
   */
  public static void validateRsaSsaPkcs1Params(RsaSsaPkcs1Params params)
      throws GeneralSecurityException {
    toHashType(params.getHashType());
  }

  /**
   * Validates RsaSsaPss's parameters.
   *
   * <ul>
   *   <li>The MGF1 hash function must be the same as the signature hash function.
   *   <li>The hash function used must be either SHA256, SHA384, or SHA512.
   *   <li>The salt length must be non-zero.
   *       <ul>
   *
   * @param params the RsaSsaPssParams protocol buffer.
   * @throws GeneralSecurityException iff it's invalid.
   */
  public static void validateRsaSsaPssParams(RsaSsaPssParams params)
      throws GeneralSecurityException {
    toHashType(params.getSigHash());
    if (params.getSigHash() != params.getMgf1Hash()) {
      throw new GeneralSecurityException("MGF1 hash is different from signature hash");
    }
    if (params.getSaltLength() < 0) {
      throw new GeneralSecurityException("salt length is negative");
    }
  }

  /**
   * Converts protobuf enum {@code HashType} to raw Java enum {@code Enums.HashType}.
   *
   * @throws GeneralSecurityException if the HashType is not SHA256, SHA384, or SHA512.
   */
  public static Enums.HashType toHashType(HashType hash) throws GeneralSecurityException {
    switch (hash) {
      case SHA256:
        return Enums.HashType.SHA256;
      case SHA384:
        return Enums.HashType.SHA384;
      case SHA512:
        return Enums.HashType.SHA512;
      default:
        break;
    }
    throw new GeneralSecurityException("unsupported hash type: " + hash.name());
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
        throw new GeneralSecurityException("unknown curve type: " + type.name());
    }
  }

  /**
   * Converts protobuf enum {@code EcdsaSignatureEncoding} to raw Java enum {code
   * EllipticCurves.EcdsaEncoding}.
   */
  public static EllipticCurves.EcdsaEncoding toEcdsaEncoding(EcdsaSignatureEncoding encoding)
      throws GeneralSecurityException {
    switch (encoding) {
      case IEEE_P1363:
        return EllipticCurves.EcdsaEncoding.IEEE_P1363;
      case DER:
        return EllipticCurves.EcdsaEncoding.DER;
      default:
        throw new GeneralSecurityException("unknown ECDSA encoding: " + encoding.name());
    }
  }

  /**
   * Returns the unsigned byte representation of the input BigInteger. BigInteger's toByteArray
   * returns a two's complement representation of non-negative integers, which might include an
   * extra zero byte at position 0 (in big endian).
   */
  public static ByteString toUnsignedIntByteString(BigInteger i) {
    byte[] twosComplement = i.toByteArray();
    if (twosComplement[0] == 0x00) {
      return ByteString.copyFrom(twosComplement, 1, twosComplement.length - 1);
    }
    return ByteString.copyFrom(twosComplement);
  }

  private SigUtil() {}
}
