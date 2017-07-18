// Copyright 2017 Google Inc.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////
package ecdsa

import (
  "fmt"
  "math/big"
  commonpb "github.com/google/tink/proto/common_go_proto"
  ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
)

var errUnsupportedEncoding = fmt.Errorf("ecdsa: unsupported encoding")

// ecdsaSignature is a struct holding r and s values of an ECDSA signature.
type EcdsaSignature struct {
  R, S *big.Int
}

// newSignature creates a new ecdsaSignature object.
func NewSignature(r, s *big.Int) *EcdsaSignature {
  return &EcdsaSignature{R: r, S: s}
}

// Encode converts the signature to the given encoding format.
// Only DER encoding is supported now.
func (sig *EcdsaSignature) Encode(encoding ecdsapb.EcdsaSignatureEncoding) ([]byte, error) {
  switch encoding {
    case ecdsapb.EcdsaSignatureEncoding_DER:
      return asn1encode(sig)
    default:
      return nil, errUnsupportedEncoding
  }
}

// NewSignatureFromBytes creates a new ECDSA signature using the given byte slice.
// The function assumes that the byte slice is the concatenation of the BigEndian
// representation of two big integer r and s.
func DecodeSignature(encodedBytes []byte,
                    encoding ecdsapb.EcdsaSignatureEncoding) (*EcdsaSignature, error) {
  switch encoding {
    case ecdsapb.EcdsaSignatureEncoding_DER:
      return asn1decode(encodedBytes)
    default:
      return nil, errUnsupportedEncoding
  }
}

// ValidatePrivateKey validates the given EcdsaPrivateKey proto.
func ValidatePrivateKey(privateKey *ecdsapb.EcdsaPrivateKey) error {
  if privateKey == nil {
    return fmt.Errorf("private key must not be nil")
  }
  if err := ValidatePublicKey(privateKey.PublicKey); err != nil {
    return err
  }
  return nil
}

// ValidatePublicKey validates the given EcdsaPublicKey proto.
func ValidatePublicKey(publicKey *ecdsapb.EcdsaPublicKey) error {
  if publicKey == nil {
    return fmt.Errorf("public key must not be nil")
  }
  if err := ValidateParams(publicKey.Params); err != nil {
    return err
  }
  return nil
}

// ValidateEcdsaParams validates ECDSA parameters.
// The hash's strength must not be weaker than the curve's strength.
// Only DER encoding is supported now.
func ValidateParams(params *ecdsapb.EcdsaParams) error {
  switch params.Encoding {
    case ecdsapb.EcdsaSignatureEncoding_DER:
      break
    default:
      return errUnsupportedEncoding
  }
  switch params.Curve {
    case commonpb.EllipticCurveType_NIST_P256:
      if params.HashType != commonpb.HashType_SHA256 {
        return fmt.Errorf("invalid hash type, expect SHA-256 or SHA-512")
      }
    case commonpb.EllipticCurveType_NIST_P384,
          commonpb.EllipticCurveType_NIST_P521:
      if params.HashType != commonpb.HashType_SHA512 {
        return fmt.Errorf("invalid hash type, expect SHA-512")
      }
    default:
      return fmt.Errorf("unsupported curve: %d", params.Curve)
  }
  return nil
}