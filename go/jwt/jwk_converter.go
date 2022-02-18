// Copyright 2022 Google LLC
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

package jwt

import (
	"fmt"
	"math/rand"

	spb "google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	jepb "github.com/google/tink/go/proto/jwt_ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	jwtECDSAPublicKeyType = "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"
)

func keysetHasID(ks *tinkpb.Keyset, keyID uint32) bool {
	for _, k := range ks.GetKey() {
		if k.GetKeyId() == keyID {
			return true
		}
	}
	return false
}

func generateUnusedID(ks *tinkpb.Keyset) uint32 {
	for {
		keyID := rand.Uint32()
		if !keysetHasID(ks, keyID) {
			return keyID
		}
	}
}

func hasItem(s *spb.Struct, name string) bool {
	if s.GetFields() == nil {
		return false
	}
	_, ok := s.Fields[name]
	return ok
}

func stringItem(s *spb.Struct, name string) (string, error) {
	fields := s.GetFields()
	if fields == nil {
		return "", fmt.Errorf("no fields")
	}
	val, ok := fields[name]
	if !ok {
		return "", fmt.Errorf("field %q not found", name)
	}
	r, ok := val.Kind.(*spb.Value_StringValue)
	if !ok {
		return "", fmt.Errorf("field %q is not a string", name)
	}
	return r.StringValue, nil
}

func listValue(s *spb.Struct, name string) (*spb.ListValue, error) {
	fields := s.GetFields()
	if fields == nil {
		return nil, fmt.Errorf("empty set")
	}
	vals, ok := fields[name]
	if !ok {
		return nil, fmt.Errorf("%q not found", name)
	}
	list, ok := vals.Kind.(*spb.Value_ListValue)
	if !ok {
		return nil, fmt.Errorf("%q is not a list", name)
	}
	if list.ListValue == nil || len(list.ListValue.GetValues()) == 0 {
		return nil, fmt.Errorf("%q list is empty", name)
	}
	return list.ListValue, nil
}

func expectStringItem(s *spb.Struct, name, value string) error {
	item, err := stringItem(s, name)
	if err != nil {
		return err
	}
	if item != value {
		return fmt.Errorf("unexpected value %q for %q", value, name)
	}
	return nil
}

func decodePoint(s *spb.Struct, name string) ([]byte, error) {
	point, err := stringItem(s, name)
	if err != nil {
		return nil, err
	}
	return base64Decode(point)
}

func validateKeyOPSIsVerify(s *spb.Struct) error {
	if !hasItem(s, "key_ops") {
		return nil
	}
	keyOPSList, err := listValue(s, "key_ops")
	if err != nil {
		return err
	}
	if len(keyOPSList.GetValues()) != 1 {
		return fmt.Errorf("key_ops size is not 1")
	}
	value, ok := keyOPSList.GetValues()[0].Kind.(*spb.Value_StringValue)
	if !ok {
		return fmt.Errorf("key_ops is not a string")
	}
	if value.StringValue != "verify" {
		return fmt.Errorf("key_ops is not equal to [\"verify\"]")
	}
	return nil
}

func validateUseIsSig(s *spb.Struct) error {
	if !hasItem(s, "use") {
		return nil
	}
	return expectStringItem(s, "use", "sig")
}

func algorithmPrefixMatch(s *spb.Struct, prefix string) error {
	alg, err := stringItem(s, "alg")
	if err != nil {
		return err
	}
	if len(alg) < len(prefix) {
		return fmt.Errorf("invalid algorithm")
	}
	if alg[0:len(prefix)] != prefix {
		return fmt.Errorf("invalid algorithm")
	}
	return nil
}

func esPublicKeyDataFromStruct(keyStruct *spb.Struct) (*tinkpb.KeyData, error) {
	alg, err := stringItem(keyStruct, "alg")
	if err != nil {
		return nil, err
	}
	curve, err := stringItem(keyStruct, "crv")
	if err != nil {
		return nil, err
	}
	var algorithm jepb.JwtEcdsaAlgorithm = jepb.JwtEcdsaAlgorithm_ES_UNKNOWN
	if alg == "ES256" && curve == "P-256" {
		algorithm = jepb.JwtEcdsaAlgorithm_ES256
	}
	if alg == "ES384" && curve == "P-384" {
		algorithm = jepb.JwtEcdsaAlgorithm_ES384
	}
	if alg == "ES512" && curve == "P-521" {
		algorithm = jepb.JwtEcdsaAlgorithm_ES512
	}
	if algorithm == jepb.JwtEcdsaAlgorithm_ES_UNKNOWN {
		return nil, fmt.Errorf("invalid algorithm %q and curve %q", alg, curve)
	}
	if hasItem(keyStruct, "d") {
		return nil, fmt.Errorf("private keys cannot be converted")
	}
	if err := expectStringItem(keyStruct, "kty", "EC"); err != nil {
		return nil, err
	}
	if err := validateUseIsSig(keyStruct); err != nil {
		return nil, err
	}
	if err := validateKeyOPSIsVerify(keyStruct); err != nil {
		return nil, err
	}
	x, err := decodePoint(keyStruct, "x")
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %v", err)
	}
	y, err := decodePoint(keyStruct, "y")
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %v", err)
	}
	var customKID *jepb.JwtEcdsaPublicKey_CustomKid = nil
	if hasItem(keyStruct, "kid") {
		kid, err := stringItem(keyStruct, "kid")
		if err != nil {
			return nil, err
		}
		customKID = &jepb.JwtEcdsaPublicKey_CustomKid{Value: kid}
	}
	pubKey := &jepb.JwtEcdsaPublicKey{
		Version:   0,
		Algorithm: algorithm,
		X:         x,
		Y:         y,
		CustomKid: customKID,
	}
	serializedPubKey, err := proto.Marshal(pubKey)
	if err != nil {
		return nil, err
	}
	return &tinkpb.KeyData{
		TypeUrl:         jwtECDSAPublicKeyType,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// TODO(b/173082704): Support RSA Key Types once Tink has RSA key managers
func keysetKeyFromStruct(val *spb.Value, keyID uint32) (*tinkpb.Keyset_Key, error) {
	keyStruct := val.GetStructValue()
	if keyStruct == nil {
		return nil, fmt.Errorf("key is not a JSON object")
	}
	if err := algorithmPrefixMatch(keyStruct, "ES"); err != nil {
		return nil, err
	}
	keyData, err := esPublicKeyDataFromStruct(keyStruct)
	if err != nil {
		return nil, err
	}
	return &tinkpb.Keyset_Key{
		KeyData:          keyData,
		Status:           tinkpb.KeyStatusType_ENABLED,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		KeyId:            keyID,
	}, nil
}

// JWKSetToPublicKeysetHandle converts a Json Web Key (JWK) set into a Tink KeysetHandle.
// It requires that all keys in the set have the "alg" field set. Currently, only
// public keys for algorithms ES256, ES384 and ES512 are supported.
// JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.
func JWKSetToPublicKeysetHandle(jwkSet []byte) (*keyset.Handle, error) {
	jwk := &spb.Struct{}
	if err := jwk.UnmarshalJSON(jwkSet); err != nil {
		return nil, err
	}
	keyList, err := listValue(jwk, "keys")
	if err != nil {
		return nil, err
	}

	ks := &tinkpb.Keyset{}
	for _, keyStruct := range keyList.GetValues() {
		key, err := keysetKeyFromStruct(keyStruct, generateUnusedID(ks))
		if err != nil {
			return nil, err
		}
		ks.Key = append(ks.Key, key)
	}
	ks.PrimaryKeyId = ks.Key[len(ks.Key)-1].GetKeyId()
	return keyset.NewHandleWithNoSecrets(ks)
}
