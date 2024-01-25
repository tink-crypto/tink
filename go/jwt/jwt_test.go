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
/////////////////////////////////////////////////////////////////////////////////

package jwt_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
)

// [START jwt-signature-example]
func Example_signAndVerify() {
	// A private keyset created with
	// "tinkey create-keyset --key-template=JWT_ES256 --out private_keyset.cfg".
	// Note that this keyset has the secret key information in cleartext.
	privateJSONKeyset := `{
		"primaryKeyId": 1742360595,
		"key": [
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
					"value": "GiBgVYdAPg3Fa2FVFymGDYrI1trHMzVjhVNEMpIxG7t0HRJGIiBeoDMF9LS5BDCh6YgqE3DjHwWwnEKEI3WpPf8izEx1rRogbjQTXrTcw/1HKiiZm2Hqv41w7Vd44M9koyY/+VsP+SAQAQ==",
					"keyMaterialType": "ASYMMETRIC_PRIVATE"
				},
				"status": "ENABLED",
				"keyId": 1742360595,
				"outputPrefixType": "TINK"
			}
		]
	}`

	// The corresponding public keyset created with
	// "tinkey create-public-keyset --in private_keyset.cfg"
	publicJSONKeyset := `{
		"primaryKeyId": 1742360595,
		"key": [
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
					"value": "EAEaIG40E1603MP9RyoomZth6r+NcO1XeODPZKMmP/lbD/kgIiBeoDMF9LS5BDCh6YgqE3DjHwWwnEKEI3WpPf8izEx1rQ==",
					"keyMaterialType": "ASYMMETRIC_PUBLIC"
				},
				"status": "ENABLED",
				"keyId": 1742360595,
				"outputPrefixType": "TINK"
			}
		]
	}`

	// Create a keyset handle from the cleartext private keyset in the previous
	// step. The keyset handle provides abstract access to the underlying keyset to
	// limit the access of the raw key material. WARNING: In practice,
	// it is unlikely you will want to use a insecurecleartextkeyset, as it implies
	// that your key material is passed in cleartext, which is a security risk.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.
	privateKeysetHandle, err := insecurecleartextkeyset.Read(
		keyset.NewJSONReader(bytes.NewBufferString(privateJSONKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the JWT Signer primitive from privateKeysetHandle.
	signer, err := jwt.NewSigner(privateKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive to create and sign a token. In this case, the primary key of the
	// keyset will be used (which is also the only key in this example).
	expiresAt := time.Now().Add(time.Hour)
	audience := "example audience"
	subject := "example subject"
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
		Audience:  &audience,
		Subject:   &subject,
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		log.Fatal(err)
	}
	token, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		log.Fatal(err)
	}

	// Create a keyset handle from the keyset containing the public key. Because the
	// public keyset does not contain any secrets, we can use [keyset.ReadWithNoSecrets].
	publicKeysetHandle, err := keyset.ReadWithNoSecrets(
		keyset.NewJSONReader(bytes.NewBufferString(publicJSONKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the Verifier primitive from publicKeysetHandle.
	verifier, err := jwt.NewVerifier(publicKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signed token.
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{ExpectedAudience: &audience})
	if err != nil {
		log.Fatal(err)
	}
	verifiedJWT, err := verifier.VerifyAndDecode(token, validator)
	if err != nil {
		log.Fatal(err)
	}

	// Extract subject claim from the token.
	if !verifiedJWT.HasSubject() {
		log.Fatal(err)
	}
	extractedSubject, err := verifiedJWT.Subject()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(extractedSubject)
	// Output: example subject
}

// [END jwt-signature-example]

// [START jwt-generate-jwks-example]
func Example_generateJWKS() {
	// A Tink keyset in JSON format with one JWT public key.
	publicJSONKeyset := `{
		"primaryKeyId": 1742360595,
		"key": [
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
					"value": "EAEaIG40E1603MP9RyoomZth6r+NcO1XeODPZKMmP/lbD/kgIiBeoDMF9LS5BDCh6YgqE3DjHwWwnEKEI3WpPf8izEx1rQ==",
					"keyMaterialType": "ASYMMETRIC_PUBLIC"
				},
				"status": "ENABLED",
				"keyId": 1742360595,
				"outputPrefixType": "TINK"
			}
		]
	}`

	// Create a keyset handle from the keyset containing the public key. Because the
	// public keyset does not contain any secrets, we can use [keyset.ReadWithNoSecrets].
	publicKeysetHandle, err := keyset.ReadWithNoSecrets(
		keyset.NewJSONReader(bytes.NewBufferString(publicJSONKeyset)))
	if err != nil {
		log.Fatal(err)
	}

	// Create a publicJWKset from publicKeysetHandle.
	publicJWKset, err := jwt.JWKSetFromPublicKeysetHandle(publicKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Remove whitespace so that we can compare it to the expected string.
	compactPublicJWKset := &bytes.Buffer{}
	err = json.Compact(compactPublicJWKset, publicJWKset)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(compactPublicJWKset.String())
	// Output:
	// {"keys":[{"alg":"ES256","crv":"P-256","key_ops":["verify"],"kid":"Z9pQEw","kty":"EC","use":"sig","x":"bjQTXrTcw_1HKiiZm2Hqv41w7Vd44M9koyY_-VsP-SA","y":"XqAzBfS0uQQwoemIKhNw4x8FsJxChCN1qT3_IsxMda0"}]}
}

// [END jwt-generate-jwks-example]

// [START jwt-verify-with-jwks-example]
func Example_verifyWithJWKS() {
	// A signed token with the subject 'example subject', audience 'example audience'.
	// and expiration on 2023-03-23.
	token := `eyJhbGciOiJFUzI1NiIsICJraWQiOiJaOXBRRXcifQ.eyJhdWQiOiJleGFtcGxlIGF1ZGllbmNlIiwgImV4cCI6MTY3OTUzMzIwMCwgInN1YiI6ImV4YW1wbGUgc3ViamVjdCJ9.ZvI0T84fJ1aouiB7n62kHOmbm0Hpfiz0JtYs15XVDT8KyoVYZ8hu_DGJUN47BqZIbuOI-rdu9TxJvutj8uF3Ow`

	// A public keyset in the JWK set format.
	publicJWKset := `{
		"keys":[
			{
				"alg":"ES256",
				"crv":"P-256",
				"key_ops":["verify"],
				"kid":"Z9pQEw",
				"kty":"EC",
				"use":"sig",
				"x":"bjQTXrTcw_1HKiiZm2Hqv41w7Vd44M9koyY_-VsP-SA",
				"y":"XqAzBfS0uQQwoemIKhNw4x8FsJxChCN1qT3_IsxMda0"
			}
		]
	}`

	// Create a keyset handle from publicJWKset.
	publicKeysetHandle, err := jwt.JWKSetToPublicKeysetHandle([]byte(publicJWKset))
	if err != nil {
		log.Fatal(err)
	}

	// Retrieve the Verifier primitive from publicKeysetHandle.
	verifier, err := jwt.NewVerifier(publicKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signed token. For this example, we use a fixed date. Usually, you would
	// either not set FixedNow, or set it to the current time.
	audience := "example audience"
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedAudience: &audience,
		FixedNow:         time.Date(2023, 3, 23, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		log.Fatal(err)
	}
	verifiedJWT, err := verifier.VerifyAndDecode(token, validator)
	if err != nil {
		log.Fatal(err)
	}

	// Extract subject claim from the token.
	if !verifiedJWT.HasSubject() {
		log.Fatal(err)
	}
	extractedSubject, err := verifiedJWT.Subject()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(extractedSubject)
	// Output: example subject
}

// [END jwt-verify-with-jwks-example]

// [START jwt-mac-example]
func Example_computeMACAndVerify() {
	// Generate a keyset handle.
	handle, err := keyset.NewHandle(jwt.HS256Template())
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Save the keyset to a safe location. DO NOT hardcode it in source
	// code.  Consider encrypting it with a remote key in a KMS.  See
	// https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets

	// Create a token and compute a MAC for it.
	expiresAt := time.Now().Add(time.Hour)
	audience := "example audience"
	customClaims := map[string]any{"custom": "my custom claim"}
	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
		Audience:     &audience,
		CustomClaims: customClaims,
		ExpiresAt:    &expiresAt,
	})
	if err != nil {
		log.Fatal(err)
	}
	mac, err := jwt.NewMAC(handle)
	if err != nil {
		log.Fatal(err)
	}
	token, err := mac.ComputeMACAndEncode(rawJWT)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the MAC.
	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{ExpectedAudience: &audience})
	if err != nil {
		log.Fatal(err)
	}
	verifiedJWT, err := mac.VerifyMACAndDecode(token, validator)
	if err != nil {
		log.Fatal(err)
	}

	// Extract a custom claim from the token.
	if !verifiedJWT.HasStringClaim("custom") {
		log.Fatal(err)
	}
	extractedCustomClaim, err := verifiedJWT.StringClaim("custom")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(extractedCustomClaim)
	// Output: my custom claim
}

// [END jwt-mac-example]
