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
package util

import (
  "fmt"
  "hash"
  "math/big"
  "encoding/hex"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
  "crypto/elliptic"
  commonpb "github.com/google/tink/proto/common_go_proto"
)

/**
 * Checks whether the given version is valid. The version is valid only if
 * it is the range [0..{@code maxExpected}]
 */
func ValidateVersion(version uint32, maxExpected uint32) error {
  if version > maxExpected {
    msg := fmt.Sprintf("key has version %v; " +
        "only keys with version in range [0..%v] are supported",
        version, maxExpected)
    return fmt.Errorf("subtle/util: " + msg)
  }
  return nil
}

/**
 * Checks if {@code sizeInBytes} is a valid AES key size.
 */
func ValidateAesKeySize(sizeInBytes uint32) error {
  switch sizeInBytes {
    case 16, 24, 32:
      return nil
    default:
      return fmt.Errorf("invalid AES key size %d", sizeInBytes)
  }
}

/**
 * Checks if {@code curveType} is valid.
 */
func ValidateCurveType(curveType commonpb.EllipticCurveType) error {
  switch curveType {
    case commonpb.EllipticCurveType_NIST_P256,
        commonpb.EllipticCurveType_NIST_P384,
        commonpb.EllipticCurveType_NIST_P521:
      return nil
    default:
      return fmt.Errorf("unsupported curve type: %v", curveType)
  }
}

/**
 * Checks if {@code hashType} is supported.
 */
func ValidateHashType(hashType commonpb.HashType) error {
  switch hashType {
    case commonpb.HashType_SHA1,
        commonpb.HashType_SHA256,
        commonpb.HashType_SHA512:
      return nil
    default:
      return fmt.Errorf("unsupported hash type: %v", hashType)
  }
}

func HashNameToHashType(name string) commonpb.HashType {
  switch name {
    case "SHA-256":
      return commonpb.HashType_SHA256
    case "SHA-512":
      return commonpb.HashType_SHA512
    case "SHA-1":
      return commonpb.HashType_SHA1
    default:
      return commonpb.HashType_UNKNOWN_HASH
  }
}

func CurveNameToCurveType(name string) commonpb.EllipticCurveType {
  switch name {
    case "secp256r1":
      return commonpb.EllipticCurveType_NIST_P256
    case "secp384r1":
      return commonpb.EllipticCurveType_NIST_P384
    case "secp521r1":
      return commonpb.EllipticCurveType_NIST_P521
    default:
      return commonpb.EllipticCurveType_UNKNOWN_CURVE
  }
}

/**
 * @return the corresponding hash function of {@code hashType}
 */
func GetHashFunc(hashType commonpb.HashType) func() hash.Hash {
  switch hashType {
    case commonpb.HashType_SHA1:
      return sha1.New
    case commonpb.HashType_SHA256:
      return sha256.New
    case commonpb.HashType_SHA512:
      return sha512.New
    default:
      return nil
  }
}

// GetCurve returns the curve object that corresponds to the given curve type.
// It returns null if the curve type is not supported.
func GetCurve(curveType commonpb.EllipticCurveType) elliptic.Curve {
  switch curveType {
    case commonpb.EllipticCurveType_NIST_P224:
      return elliptic.P224()
    case commonpb.EllipticCurveType_NIST_P256:
      return elliptic.P256()
    case commonpb.EllipticCurveType_NIST_P384:
      return elliptic.P384()
    case commonpb.EllipticCurveType_NIST_P521:
      return elliptic.P521()
    default:
      return nil
  }
}

// GetHash calculates a hash of the given data using the given hash function.
func GetHash(hashType commonpb.HashType, data []byte) []byte {
  hashFunc := GetHashFunc(hashType)
  if hashFunc == nil {
    return nil
  }
  h := hashFunc()
  h.Write(data)
  ret := h.Sum(nil)
  return ret
}

func NewBigIntFromHex(s string) (*big.Int, error) {
  if len(s)%2 == 1 {
    s = "0" + s
  }
  b, err := hex.DecodeString(s)
  if err != nil {
    return nil, err
  }
  ret := new(big.Int).SetBytes(b)
  return ret, nil
}