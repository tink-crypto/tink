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

package jwt_test

import (
	"fmt"
	"log"
	"time"

	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
)

func Example_signAndVerify() {
	// Generate a private keyset handle.
	handlePriv, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		log.Fatal(err)
	}

	// TODO: Save the private keyset to a safe location. DO NOT hardcode it in
	// source code.  Consider encrypting it with a remote key in a KMS.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets

	// Get a public keyset handle from the private keyset handle.
	handlePub, err := handlePriv.Public()
	if err != nil {
		log.Fatal(err)
	}

	// Create and sign a token.
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
	signer, err := jwt.NewSigner(handlePriv)
	if err != nil {
		log.Fatal(err)
	}
	token, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signed token.
	verifier, err := jwt.NewVerifier(handlePub)
	if err != nil {
		log.Fatal(err)
	}
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
	customClaims := map[string]interface{}{"custom": "my custom claim"}
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
