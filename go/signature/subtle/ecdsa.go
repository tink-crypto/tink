// Copyright 2020 Google LLC
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

package subtle

import (
	"errors"
	"fmt"
	"math/big"
)

var errUnsupportedEncoding = errors.New("ecdsa: unsupported encoding")

// ECDSASignature is a struct holding the r and s values of an ECDSA signature.
type ECDSASignature struct {
	R, S *big.Int
}

// NewECDSASignature creates a new ECDSASignature instance.
func NewECDSASignature(r, s *big.Int) *ECDSASignature {
	return &ECDSASignature{R: r, S: s}
}

// EncodeECDSASignature converts the signature to the given encoding format.
func (sig *ECDSASignature) EncodeECDSASignature(encoding, curveName string) ([]byte, error) {
	var enc []byte
	var err error
	switch encoding {
	case "IEEE_P1363":
		enc, err = ieeeP1363Encode(sig, curveName)
	case "DER":
		enc, err = asn1encode(sig)
	default:
		err = errUnsupportedEncoding
	}
	if err != nil {
		return nil, fmt.Errorf("ecdsa: can't convert ECDSA signature to %s encoding: %v", encoding, err)
	}
	return enc, nil
}

// DecodeECDSASignature creates a new ECDSA signature using the given byte slice.
// The function assumes that the byte slice is the concatenation of the BigEndian
// representation of two big integer r and s.
func DecodeECDSASignature(encodedBytes []byte, encoding string) (*ECDSASignature, error) {
	var sig *ECDSASignature
	var err error
	switch encoding {
	case "IEEE_P1363":
		sig, err = ieeeP1363Decode(encodedBytes)
	case "DER":
		sig, err = asn1decode(encodedBytes)
	default:
		err = errUnsupportedEncoding
	}
	if err != nil {
		return nil, fmt.Errorf("ecdsa: %s", err)
	}
	return sig, nil
}

// ValidateECDSAParams validates ECDSA parameters.
// The hash's strength must not be weaker than the curve's strength.
// DER and IEEE_P1363 encodings are supported.
func ValidateECDSAParams(hashAlg string, curve string, encoding string) error {
	switch encoding {
	case "DER":
	case "IEEE_P1363":
	default:
		return errUnsupportedEncoding
	}
	switch curve {
	case "NIST_P256":
		if hashAlg != "SHA256" {
			return errors.New("invalid hash type, expect SHA-256")
		}
	case "NIST_P384":
		if hashAlg != "SHA384" && hashAlg != "SHA512" {
			return errors.New("invalid hash type, expect SHA-384 or SHA-512")
		}
	case "NIST_P521":
		if hashAlg != "SHA512" {
			return errors.New("invalid hash type, expect SHA-512")
		}
	default:
		return fmt.Errorf("unsupported curve: %s", curve)
	}
	return nil
}
