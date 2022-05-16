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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	spb "google.golang.org/protobuf/types/known/structpb"
	tpb "github.com/google/tink/go/proto/tink_go_proto"
)

// keyID returns the keyID in big endian format base64 encoded if the key output prefix is of type Tink or nil otherwise.
func keyID(keyID uint32, outPrefixType tpb.OutputPrefixType) *string {
	if outPrefixType != tpb.OutputPrefixType_TINK {
		return nil
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, keyID)
	s := base64Encode(buf)
	return &s
}

// createUnsigned creates an unsigned JWT by created the header/payload, encoding them to a websafe base64 encoded string and concatenating.
func createUnsigned(rawJWT *RawJWT, algo string, tinkKID *string, customKID *string) (string, error) {
	if rawJWT == nil {
		return "", fmt.Errorf("rawJWT is nil")
	}
	var typeHeader *string = nil
	if rawJWT.HasTypeHeader() {
		th, err := rawJWT.TypeHeader()
		if err != nil {
			return "", err
		}
		typeHeader = &th
	}
	if customKID != nil && tinkKID != nil {
		return "", fmt.Errorf("TINK Keys are not allowed to have a kid value set")
	}
	if tinkKID != nil {
		customKID = tinkKID
	}
	encodedHeader, err := createHeader(algo, typeHeader, customKID)
	if err != nil {
		return "", err
	}
	payload, err := rawJWT.JSONPayload()
	if err != nil {
		return "", err
	}
	return dotConcat(encodedHeader, base64Encode(payload)), nil
}

// combineUnsignedAndSignature combines the token with the raw signature to provide a signed token.
func combineUnsignedAndSignature(unsigned string, signature []byte) string {
	return dotConcat(unsigned, base64Encode(signature))
}

// splitSignedCompact extracts the witness and usigned JWT.
func splitSignedCompact(compact string) ([]byte, string, error) {
	i := strings.LastIndex(compact, ".")
	if i < 0 {
		return nil, "", fmt.Errorf("invalid token")
	}
	witness, err := base64Decode(compact[i+1:])
	if err != nil {
		return nil, "", fmt.Errorf("%q: %v", compact[i+1:], err)
	}
	if len(witness) == 0 {
		return nil, "", fmt.Errorf("empty signature")
	}
	unsigned := compact[0:i]
	if len(unsigned) == 0 {
		return nil, "", fmt.Errorf("empty content")
	}
	if strings.Count(unsigned, ".") != 1 {
		return nil, "", fmt.Errorf("only tokens in JWS compact serialization formats are supported")
	}
	return witness, unsigned, nil
}

// decodeUnsignedTokenAndValidateHeader verifies the header on an unsigned JWT and decodes the payload into a RawJWT.
// Expects the token to be in compact serialization format. The signature should be verified before calling this function.
func decodeUnsignedTokenAndValidateHeader(unsigned, algorithm string, tinkKID, customKID *string) (*RawJWT, error) {
	parts := strings.Split(unsigned, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("only tokens in JWS compact serialization formats are supported")
	}
	jsonHeader, err := base64Decode(parts[0])
	if err != nil {
		return nil, err
	}
	header, err := jsonToStruct(jsonHeader)
	if err != nil {
		return nil, err
	}
	if err := validateHeader(header, algorithm, tinkKID, customKID); err != nil {
		return nil, err
	}
	typeHeader, err := extractTypeHeader(header)
	if err != nil {
		return nil, err
	}
	jsonPayload, err := base64Decode(parts[1])
	if err != nil {
		return nil, err
	}
	return NewRawJWTFromJSON(typeHeader, jsonPayload)
}

// base64Encode encodes a byte array into a base64 URL safe string with no padding.
func base64Encode(content []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(content)
}

// base64Decode decodes a URL safe base64 encoded string into a byte array ignoring padding.
func base64Decode(content string) ([]byte, error) {
	for _, c := range content {
		if !isValidURLsafeBase64Char(c) {
			return nil, fmt.Errorf("invalid encoding")
		}
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(content)
}

func isValidURLsafeBase64Char(c rune) bool {
	return (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) ||
		((c >= '0') && (c <= '9')) || ((c == '-') || (c == '_')))
}

func dotConcat(a, b string) string {
	return fmt.Sprintf("%s.%s", a, b)
}

func jsonToStruct(jsonPayload []byte) (*spb.Struct, error) {
	payload := &spb.Struct{}
	if err := payload.UnmarshalJSON(jsonPayload); err != nil {
		return nil, err
	}
	return payload, nil
}

func extractTypeHeader(header *spb.Struct) (*string, error) {
	fields := header.GetFields()
	if fields == nil {
		return nil, fmt.Errorf("header contains no fields")
	}
	val, ok := fields["typ"]
	if !ok {
		return nil, nil
	}
	str, ok := val.Kind.(*spb.Value_StringValue)
	if !ok {
		return nil, fmt.Errorf("type header isn't a string")
	}
	return &str.StringValue, nil
}

func createHeader(algorithm string, typeHeader, kid *string) (string, error) {
	header := &spb.Struct{
		Fields: map[string]*spb.Value{
			"alg": spb.NewStringValue(algorithm),
		},
	}
	if typeHeader != nil {
		header.Fields["typ"] = spb.NewStringValue(*typeHeader)
	}
	if kid != nil {
		header.Fields["kid"] = spb.NewStringValue(*kid)
	}
	jsonHeader, err := header.MarshalJSON()
	if err != nil {
		return "", err
	}
	return base64Encode(jsonHeader), nil
}

func validateHeader(header *spb.Struct, algorithm string, tinkKID, customKID *string) error {
	fields := header.GetFields()
	if fields == nil {
		return fmt.Errorf("header contains no fields")
	}
	alg, err := headerStringField(fields, "alg")
	if err != nil {
		return err
	}
	if alg != algorithm {
		return fmt.Errorf("invalid alg")
	}
	if _, ok := fields["crit"]; ok {
		return fmt.Errorf("all tokens with crit headers are rejected")
	}
	if tinkKID != nil && customKID != nil {
		return fmt.Errorf("custom_kid can only be set for RAW keys")
	}
	_, hasKID := fields["kid"]
	if tinkKID != nil && !hasKID {
		return fmt.Errorf("missing kid in header")
	}
	if tinkKID != nil {
		return validateKIDInHeader(fields, tinkKID)
	}
	if hasKID && customKID != nil {
		return validateKIDInHeader(fields, customKID)
	}
	return nil
}

func validateKIDInHeader(fields map[string]*spb.Value, kid *string) error {
	headerKID, err := headerStringField(fields, "kid")
	if err != nil {
		return err
	}
	if headerKID != *kid {
		return fmt.Errorf("invalid kid header")
	}
	return nil
}

func headerStringField(fields map[string]*spb.Value, name string) (string, error) {
	val, ok := fields[name]
	if !ok {
		return "", fmt.Errorf("header is missing %q", name)
	}
	str, ok := val.Kind.(*spb.Value_StringValue)
	if !ok {
		return "", fmt.Errorf("%q header isn't a string", name)
	}
	return str.StringValue, nil
}
