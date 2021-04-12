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

package fakekms_test

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/testing/fakekms"
)

const keyURI = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"
const anotherKeyURI = "fake-kms://CLHW_5cHElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIZ-2h9InfZTbbkJjaJBsVgYARABGLHW_5cHIAE"

func TestValidKeyURIs(t *testing.T) {
	newKeyURI, err := fakekms.NewKeyURI()
	if err != nil {
		t.Fatal(err)
	}
	var testCases = []string{
		keyURI,
		anotherKeyURI,
		newKeyURI,
	}
	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			client, err := fakekms.NewClient(tc)
			if err != nil {
				t.Fatalf("testutil.NewFakeKMSClient(keyURI) failed: %v", err)
			}
			if !client.Supported(tc) {
				t.Fatalf("client.Supported(keyURI) is false, want true")
			}
			primitive, err := client.GetAEAD(tc)
			if err != nil {
				t.Fatalf("client.GetAEAD(keyURI) failed: %v", err)
			}

			plaintext := []byte("some data to encrypt")
			aad := []byte("extra data to authenticate")
			ciphertext, err := primitive.Encrypt(plaintext, aad)
			if err != nil {
				t.Fatalf("primitive.Encrypt(plaintext, aad) failed: %v", err)
			}
			decrypted, err := primitive.Decrypt(ciphertext, aad)
			if err != nil {
				t.Fatalf("primitive.Decrypt(ciphertext, aad) failed: %v", err)
			}
			if !bytes.Equal(plaintext, decrypted) {
				t.Fatalf("decrypted data doesn't match plaintext, got: %q, want: %q", decrypted, plaintext)
			}
		})
	}
}

func TestBadUriPrefix(t *testing.T) {
	_, err := fakekms.NewClient("bad-prefix://encodedkeyset")
	if err == nil {
		t.Fatalf("fakekms.NewClient('bad-prefix://encodedkeyset') succeeded, want fail")
	}
}

func TestValidPrefix(t *testing.T) {
	uriPrefix := "fake-kms://CM2b" // is a prefix of keyURI
	client, err := fakekms.NewClient(uriPrefix)
	if err != nil {
		t.Fatalf("fakekms.NewClient(uriPrefix) failed: %v", err)
	}
	if !client.Supported(keyURI) {
		t.Fatalf("client with URI prefix %s should support key URI %s", uriPrefix, keyURI)
	}
	_, err = client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(anotherKeyURI) failed: %v", err)
	}
}

func TestInvalidPrefix(t *testing.T) {
	uriPrefix := "fake-kms://CM2x" // is not a prefix of keyURI
	client, err := fakekms.NewClient(uriPrefix)
	if err != nil {
		t.Fatalf("fakekms.NewClient(uriPrefix) failed: %v", err)
	}
	if client.Supported(keyURI) {
		t.Fatalf("client with URI prefix %s should not support key URI %s", uriPrefix, keyURI)
	}
	_, err = client.GetAEAD(keyURI)
	if err == nil {
		t.Fatalf("client.GetAEAD(keyURI) succeeded, want fail")
	}
}

func TestGetAeadFailsWithBadKeysetEncoding(t *testing.T) {
	client, err := fakekms.NewClient("fake-kms://bad")
	if err != nil {
		t.Fatalf("fakekms.NewClient('fake-kms://bad') failed: %v", err)
	}
	_, err = client.GetAEAD("fake-kms://badencoding")
	if err == nil {
		t.Fatalf("client.GetAEAD('fake-kms://badencoding') succeeded, want fail")
	}
}
