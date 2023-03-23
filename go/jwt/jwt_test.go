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
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/jwt"
	"github.com/google/tink/go/keyset"
)

func Example_signAndVerify() {
	// A private keyset created with
	// "tinkey create-keyset --key-template=JWT_RS256_2048_F4 --out private_keyset.cfg".
	// Note that this keyset has the secret key information in cleartext.
	privateJSONKeyset := `{
		"primaryKeyId": 185188009,
		"key": [
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
					"value": "EosCEAEagQIAs9iifvWObNLbP+x7zupVIYTdHKba4VFgJEnnGtIII21R+KGddTdvNGAokd4GPrFk1GDPitHrAAoW1+NWrafsEUi2J9Sy3uwEyarsKDggewoBCNg2fcWAiZXplPjUyTlhrLvTuyrcL/mGPy+ib7bdmov+D2EP+rKUH6/ydtQGiyHRR3uurTUWfrMD1/6WaBVfngpy5Pxs2nuHXRmBHQKWmPfvErgr4abdjhKDaWIuxzSise1CSAbiWTNcxpIuFYZgPjgQzpqeh93LUXIX9YJds/bhHtXqRdxk6yTisloHOZETItK/rHCCE25dLkkaJ2Li7AtnJdBc6tEUNiuFj2JCjSIDAQABGoACT2lWxwySaQbp/N3lBUZ/dJ+AKsiaWWdfNmbTfwpCwbHhwhFKv5lMpynWgCIzS7d0uDpPKhLq20eZMpaVjXRaTn92vzuyB7DbpFiukkvGO839CvS9iueMjDP/weHlwzxtHqKJKVoRg7WAS6Iy7XUngLhT5GKNdbsooJ1GSKXyhbgWyMcspKSQe4lZXUntVMK5z4iLNmcQwsBp8yM55mZra13TXowob/E/wd+tGiABCn6CDt8G1gXzWDaoF2tt6WhSGZbXUVGagmoea/BWeAuJyKSSi5h+uPpc5SPhGvyKfSEVaCs2QeM7/UIXhzAcx2j/VqySb6y9EbSiJfy8vr49QSKBAQD+AbFCGHd9kZ5LIQrfe9caOxS9pQPdFkBJESw0C3x2uBIg8awiQsuVXMeEgyGLyWBZoi2x98OMSR9OzCuSLtb7Nv0Wqn0LUj4WPRdmg//uLeD3O2rcVRIR4db/B8WvXnK2uQsqwGDyh4BepGvprXQPYMX2uwnBGL2ccS2De53HJSqBAQC1QfOi4egjmlmXqJLpISUSN1NixkIi8EJHaZZ0YrbaRrEyiJczthcazNHFt6gzgOcosFaKaZeqps4Tet+5NgS7eh7RzLQ2+cfT4ewpT2ExJ4NsOy8XDqD6GRjliLxjGAoUf24s3B+3LLACPiQjeeZGJP0ivh384WabyXXxRgHFSTKBAQChl7gKIYCbHPHEQAAnzyQ4Js/6GinMFCTPlyI09f23lUDLPpRQs4fKvNydO8Myp+ko/NjvOH1qGPbW7WLmu+++n+wA6HNmqWqgQTtK170Q7JULE/zWsTQutitN0cb82yxFfJFTIFJM2NFc5GNWpSeJxPoMDk+VTcUK6qGW3SSyFTqBAQCeaPFA3SZAV1kNjio2zNzVOr0JijOqzUdfmgv/03Xy9e1POMjMTMuMhIygu42o1XMwwEwh037Vicp4g96aw3cHUgc1XC30DgByUPRQdit/BgV5xY+2GvbdHKoBkKrz/8Jvf58OXaLqN4frrdtvlc2GaDVC89zJcUR3ym3lW0WY4UKBAQD6MCruwXaxXJMxjtlH1YT5ow4R5neeiswNfGj4Ta/WbWyiVA60zpdNbGqH+etmiHY8+aBb/H4O9+JhOcBtlMLN4UlK1jg8wPSemZjsIPiUZXHkeIUa2RTUSz90wgz7aOqC0lYsLLFaJNWs54fC9LpZ0JzoqYDI8iDPnlE7xaag9g==",
					"keyMaterialType": "ASYMMETRIC_PRIVATE"
				},
				"status": "ENABLED",
				"keyId": 185188009,
				"outputPrefixType": "TINK"
			}
		]
	}`

	// The corresponding public keyset created with
	// "tinkey create-public-keyset --in private_keyset.cfg"
	publicJSONKeyset := `{
		"primaryKeyId": 185188009,
		"key": [
			{
				"keyData": {
					"typeUrl": "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
					"value": "EAEagQIAs9iifvWObNLbP+x7zupVIYTdHKba4VFgJEnnGtIII21R+KGddTdvNGAokd4GPrFk1GDPitHrAAoW1+NWrafsEUi2J9Sy3uwEyarsKDggewoBCNg2fcWAiZXplPjUyTlhrLvTuyrcL/mGPy+ib7bdmov+D2EP+rKUH6/ydtQGiyHRR3uurTUWfrMD1/6WaBVfngpy5Pxs2nuHXRmBHQKWmPfvErgr4abdjhKDaWIuxzSise1CSAbiWTNcxpIuFYZgPjgQzpqeh93LUXIX9YJds/bhHtXqRdxk6yTisloHOZETItK/rHCCE25dLkkaJ2Li7AtnJdBc6tEUNiuFj2JCjSIDAQAB",
					"keyMaterialType": "ASYMMETRIC_PUBLIC"
				},
				"status": "ENABLED",
				"keyId": 185188009,
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

func Example_verifyWithJWKS() {
	// A signed token with the subject 'example subject', audience 'example audience'.
	// and expiration on 2023-03-23.
	token := `eyJhbGciOiJSUzI1NiIsImtpZCI6IkN3bS1xUSJ9.eyJhdWQiOiJleGFtcGxlIGF1ZGllbmNlIiwiZXhwIjoxNjc5NTcyODQzLCJzdWIiOiJleGFtcGxlIHN1YmplY3QifQ.dUPhvdmEnGuyESLBQn5OC3QmnRcJlcMfxDPsZ2wfqBK9poQag94xLxBnkzSZnhPP2gQcIt2aOCFeftL1MK3boI3g887J2hZ6hJmeABVi82YGK16P6LIgZuALdjiUcyexus5sxcEo2iuELzUy0hOzS2dDQWOoWCznltGFuavNQGW8A2365JScCsQeoDLAa-IX89vJww0uQVRZ8AxYigLJ5DhILtu-Lssq5sSpT28XASAMzafuYvAI60Cw8nvxTaheRA8AkTI9DWERV4Z-0UQNV2O61U6_24hkjIYCGpuz8_5vBB-W3jijIdWf8J1BNyBfjNeh9eXgSZh8J3wBCEb98Q`

	// A public keyset in the JWK set format.
	publicJWKset := `{
		"keys":[
			{
				"alg":"RS256",
				"e":"AQAB",
				"key_ops":["verify"],
				"kid":"Cwm-qQ",
				"kty":"RSA",
				"n":"ALPYon71jmzS2z_se87qVSGE3Rym2uFRYCRJ5xrSCCNtUfihnXU3bzRgKJHeBj6xZNRgz4rR6wAKFtfjVq2n7BFItifUst7sBMmq7Cg4IHsKAQjYNn3FgImV6ZT41Mk5Yay707sq3C_5hj8vom-23ZqL_g9hD_qylB-v8nbUBosh0Ud7rq01Fn6zA9f-lmgVX54KcuT8bNp7h10ZgR0Clpj37xK4K-Gm3Y4Sg2liLsc0orHtQkgG4lkzXMaSLhWGYD44EM6anofdy1FyF_WCXbP24R7V6kXcZOsk4rJaBzmREyLSv6xwghNuXS5JGidi4uwLZyXQXOrRFDYrhY9iQo0",
				"use":"sig"
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
