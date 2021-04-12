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

package subtle_test

import (
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/google/tink/go/signature/subtle"
	"github.com/google/tink/go/subtle/random"
)

type paramsTestECDSA struct {
	hash     string
	curve    string
	encoding string
}

func TestECDSAEncodeDecodeDER(t *testing.T) {
	nTest := 1000
	for i := 0; i < nTest; i++ {
		sig := newECDSARandomSignature()
		encoding := "DER"
		encoded, err := sig.EncodeECDSASignature(encoding, "P-256")
		if err != nil {
			t.Errorf("unexpected error during encoding: %s", err)
		}
		// first byte is 0x30
		if encoded[0] != byte(0x30) {
			t.Errorf("first byte is incorrect, expected 48, got %v", encoded[0])
		}
		// tag is 2
		if encoded[2] != byte(2) || encoded[4+encoded[3]] != byte(2) {
			t.Errorf("expect tag to be 2 (integer), got %d and %d", encoded[2], encoded[4+encoded[3]])
		}
		// length
		if len(encoded) != int(encoded[1])+2 {
			t.Errorf("incorrect length, expected %d, got %d", len(encoded), encoded[1]+2)
		}
		decodedSig, err := subtle.DecodeECDSASignature(encoded, encoding)
		if err != nil {
			t.Errorf("unexpected error during decoding: %s", err)
		}
		if decodedSig.R.Cmp(sig.R) != 0 || decodedSig.S.Cmp(sig.S) != 0 {
			t.Errorf("decoded signature doesn't match original value")
		}
	}
}

func TestECDSAEncodeDecodeIEEEP1363(t *testing.T) {
	nTest := 1000
	for i := 0; i < nTest; i++ {
		sig := newECDSARandomSignature()
		encoding := "IEEE_P1363"
		encoded, err := sig.EncodeECDSASignature(encoding, "P-256")
		if err != nil {
			t.Errorf("unexpected error during encoding: %s", err)
		}
		if len(encoded) != 64 {
			t.Errorf("incorrect length, expected %d, got %d", 64, len(encoded))
		}
		if len(sig.R.Bytes()) < 32 {
			expectedZeros := 32 - len(sig.R.Bytes())
			for i := 0; i < expectedZeros; i++ {
				if encoded[i] != 0 {
					t.Errorf("expect byte %d to be 0, got %d. encoded data = %s", i, encoded[i], hex.Dump(encoded))
				}
			}
		}
		if len(sig.S.Bytes()) < 32 {
			expectedZeros := 32 - len(sig.S.Bytes())
			for i := 32; i < (32 + expectedZeros); i++ {
				if encoded[i] != 0 {
					t.Errorf("expect byte %d to be 0, got %d. encoded data = %s", i, encoded[i], hex.Dump(encoded))
				}
			}
		}
		decodedSig, err := subtle.DecodeECDSASignature(encoded, encoding)
		if err != nil {
			t.Errorf("unexpected error during decoding: %s", err)
		}
		if decodedSig.R.Cmp(sig.R) != 0 || decodedSig.S.Cmp(sig.S) != 0 {
			t.Errorf("decoded signature doesn't match original value")
		}
	}
}

func TestECDSAEncodeWithInvalidInput(t *testing.T) {
	sig := newECDSARandomSignature()
	_, err := sig.EncodeECDSASignature("UNKNOWN_ENCODING", "P-256")
	if err == nil {
		t.Errorf("expect an error when encoding is invalid")
	}
}

func TestECDSADecodeWithInvalidInput(t *testing.T) {
	var sig *subtle.ECDSASignature
	var encoded []byte
	encoding := "DER"

	// modified first byte
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding, "P-256")
	encoded[0] = 0x31
	if _, err := subtle.DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when first byte is not 0x30")
	}
	// modified tag
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding, "P-256")
	encoded[2] = encoded[2] + 1
	if _, err := subtle.DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when tag is modified")
	}
	// modified length
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding, "P-256")
	encoded[1] = encoded[1] + 1
	if _, err := subtle.DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when length is modified")
	}
	// append unused 0s
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding, "P-256")
	tmp := make([]byte, len(encoded)+4)
	copy(tmp, encoded)
	if _, err := subtle.DecodeECDSASignature(tmp, encoding); err == nil {
		t.Errorf("expect an error when unused 0s are appended to signature")
	}
	// a struct with three numbers
	randomStruct := struct{ X, Y, Z *big.Int }{
		X: new(big.Int).SetBytes(random.GetRandomBytes(32)),
		Y: new(big.Int).SetBytes(random.GetRandomBytes(32)),
		Z: new(big.Int).SetBytes(random.GetRandomBytes(32)),
	}
	encoded, _ = asn1.Marshal(randomStruct)
	if _, err := subtle.DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when input is not an ECDSASignature")
	}
}

func TestECDSAValidateParams(t *testing.T) {
	params := genECDSAValidParams()
	for i := 0; i < len(params); i++ {
		if err := subtle.ValidateECDSAParams(params[i].hash, params[i].curve, params[i].encoding); err != nil {
			t.Errorf("unexpected error for valid params: %s, i = %d", err, i)
		}
	}
	params = genECDSAInvalidParams()
	for i := 0; i < len(params); i++ {
		if err := subtle.ValidateECDSAParams(params[i].hash, params[i].curve, params[i].encoding); err == nil {
			t.Errorf("expect an error when params are invalid, i = %d", i)
		}
	}
}

func genECDSAInvalidParams() []paramsTestECDSA {
	encodings := []string{"DER", "IEEE_P1363"}
	testCases := []paramsTestECDSA{
		// invalid encoding
		{hash: "SHA256", curve: "NIST_P256", encoding: "UNKNOWN_ENCODING"},
	}
	for _, encoding := range encodings {
		testCases = append(testCases,
			// invalid curve
			paramsTestECDSA{hash: "SHA256", curve: "UNKNOWN_CURVE", encoding: encoding},
			// invalid hash: P256 and SHA-512
			paramsTestECDSA{hash: "SHA512", curve: "NIST_P256", encoding: encoding},
			// invalid hash: P521 and SHA-256
			paramsTestECDSA{hash: "SHA256", curve: "NIST_P521", encoding: encoding},
			// invalid hash: P384 and SHA-256
			paramsTestECDSA{hash: "SHA256", curve: "NIST_P384", encoding: encoding},
		)
	}
	return testCases
}

func genECDSAValidParams() []paramsTestECDSA {
	return []paramsTestECDSA{
		{hash: "SHA256", curve: "NIST_P256", encoding: "DER"},
		{hash: "SHA256", curve: "NIST_P256", encoding: "IEEE_P1363"},
		{hash: "SHA384", curve: "NIST_P384", encoding: "DER"},
		{hash: "SHA384", curve: "NIST_P384", encoding: "IEEE_P1363"},
		{hash: "SHA512", curve: "NIST_P384", encoding: "DER"},
		{hash: "SHA512", curve: "NIST_P384", encoding: "IEEE_P1363"},
		{hash: "SHA512", curve: "NIST_P521", encoding: "DER"},
		{hash: "SHA512", curve: "NIST_P521", encoding: "IEEE_P1363"},
	}
}

func newECDSARandomSignature() *subtle.ECDSASignature {
	r := new(big.Int).SetBytes(random.GetRandomBytes(32))
	s := new(big.Int).SetBytes(random.GetRandomBytes(32))
	return subtle.NewECDSASignature(r, s)
}
