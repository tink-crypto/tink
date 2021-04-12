// Copyright 2019 Google LLC
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

package signature

import (
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
)

// getECDSAParamNames returns the string representations of each parameter in
// the given ECDSAParams.
func getECDSAParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.HashType)]
	curveName := commonpb.EllipticCurveType_name[int32(params.Curve)]
	encodingName := ecdsapb.EcdsaSignatureEncoding_name[int32(params.Encoding)]
	return hashName, curveName, encodingName
}

// newECDSAPrivateKey creates a ECDSAPrivateKey with the specified paramaters.
func newECDSAPrivateKey(version uint32,
	publicKey *ecdsapb.EcdsaPublicKey,
	keyValue []byte) *ecdsapb.EcdsaPrivateKey {
	return &ecdsapb.EcdsaPrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

// newECDSAPublicKey creates a ECDSAPublicKey with the specified paramaters.
func newECDSAPublicKey(version uint32,
	params *ecdsapb.EcdsaParams,
	x []byte, y []byte) *ecdsapb.EcdsaPublicKey {
	return &ecdsapb.EcdsaPublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}
