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

package signature

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

// asn1encode encodes the given ECDSA signature using ASN.1 encoding.
func asn1encode(sig *ECDSASignature) ([]byte, error) {
	ret, err := asn1.Marshal(*sig)
	if err != nil {
		return nil, fmt.Errorf("asn.1 encoding failed")
	}
	return ret, nil
}

var errAsn1Decoding = fmt.Errorf("asn.1 decoding failed")

// asn1decode verifies the given ECDSA signature and decodes it if it is valid.
// Since asn1.Unmarshal() doesn't do a strict verification on its input, it will
// accept signatures with trailing data. Thus, we add an additional check to make sure
// that the input follows strict DER encoding: after unmarshalling the signature bytes,
// we marshal the obtained signature object again. Since DER encoding is deterministic,
// we expect that the obtained bytes would be equal to the input.
func asn1decode(b []byte) (*ECDSASignature, error) {
	// parse the signature
	sig := new(ECDSASignature)
	_, err := asn1.Unmarshal(b, sig)
	if err != nil {
		return nil, errAsn1Decoding
	}
	// encode the signature again
	encoded, err := asn1.Marshal(*sig)
	if err != nil {
		return nil, errAsn1Decoding
	}
	if !bytes.Equal(b, encoded) {
		return nil, errAsn1Decoding
	}
	return sig, nil
}
