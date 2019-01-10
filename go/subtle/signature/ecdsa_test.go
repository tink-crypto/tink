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

package signature_test

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/tink/go/subtle/random"
	. "github.com/google/tink/go/subtle/signature"
)

type paramsTest struct {
	hash     string
	curve    string
	encoding string
}

var _ = fmt.Println

func TestECDSAEncodeDecode(t *testing.T) {
	nTest := 1000
	for i := 0; i < nTest; i++ {
		sig := newECDSARandomSignature()
		encoding := "DER"
		encoded, err := sig.EncodeECDSASignature(encoding)
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
		decodedSig, err := DecodeECDSASignature(encoded, encoding)
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
	_, err := sig.EncodeECDSASignature("UNKNOWN_ENCODING")
	if err == nil {
		t.Errorf("expect an error when encoding is invalid")
	}
}

func TestECDSADecodeWithInvalidInput(t *testing.T) {
	var sig *ECDSASignature
	var encoded []byte
	encoding := "DER"

	// modified first byte
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding)
	encoded[0] = 0x31
	if _, err := DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when first byte is not 0x30")
	}
	// modified tag
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding)
	encoded[2] = encoded[2] + 1
	if _, err := DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when tag is modified")
	}
	// modified length
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding)
	encoded[1] = encoded[1] + 1
	if _, err := DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when length is modified")
	}
	// append unused 0s
	sig = newECDSARandomSignature()
	encoded, _ = sig.EncodeECDSASignature(encoding)
	tmp := make([]byte, len(encoded)+4)
	copy(tmp, encoded)
	if _, err := DecodeECDSASignature(tmp, encoding); err == nil {
		t.Errorf("expect an error when unused 0s are appended to signature")
	}
	// a struct with three numbers
	randomStruct := struct{ X, Y, Z *big.Int }{
		X: new(big.Int).SetBytes(random.GetRandomBytes(32)),
		Y: new(big.Int).SetBytes(random.GetRandomBytes(32)),
		Z: new(big.Int).SetBytes(random.GetRandomBytes(32)),
	}
	encoded, _ = asn1.Marshal(randomStruct)
	if _, err := DecodeECDSASignature(encoded, encoding); err == nil {
		t.Errorf("expect an error when input is not an ECDSASignature")
	}
}

func TestECDSAValidateParams(t *testing.T) {
	params := genECDSAValidParams()
	for i := 0; i < len(params); i++ {
		if err := ValidateECDSAParams(params[i].hash, params[i].curve, params[i].encoding); err != nil {
			t.Errorf("unexpected error for valid params: %s, i = %d", err, i)
		}
	}
	params = genECDSAInvalidParams()
	for i := 0; i < len(params); i++ {
		if err := ValidateECDSAParams(params[i].hash, params[i].curve, params[i].encoding); err == nil {
			t.Errorf("expect an error when params are invalid, i = %d", i)
		}
	}
}

func genECDSAInvalidParams() []paramsTest {
	return []paramsTest{
		// invalid encoding
		paramsTest{hash: "SHA256", curve: "NIST_P256", encoding: "UNKNOWN_ENCODING"},
		// invalid curve
		paramsTest{hash: "SHA256", curve: "UNKNOWN_CURVE", encoding: "DER"},
		// invalid hash: P256 and SHA-512
		paramsTest{hash: "SHA512", curve: "NIST_P256", encoding: "DER"},
		// invalid hash: P521 and SHA-256
		paramsTest{hash: "SHA256", curve: "NIST_P521", encoding: "DER"},
		// invalid hash: P384 and SHA-256
		paramsTest{hash: "SHA256", curve: "NIST_P384", encoding: "DER"},
	}
}

func genECDSAValidParams() []paramsTest {
	return []paramsTest{
		paramsTest{hash: "SHA256", curve: "NIST_P256", encoding: "DER"},
		paramsTest{hash: "SHA512", curve: "NIST_P384", encoding: "DER"},
		paramsTest{hash: "SHA512", curve: "NIST_P521", encoding: "DER"},
	}
}

func newECDSARandomSignature() *ECDSASignature {
	r := new(big.Int).SetBytes(random.GetRandomBytes(32))
	s := new(big.Int).SetBytes(random.GetRandomBytes(32))
	return NewECDSASignature(r, s)
}
