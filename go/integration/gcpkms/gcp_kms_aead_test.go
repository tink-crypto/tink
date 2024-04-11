// Copyright 2024 Google Inc.
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

package gcpkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

func initializeServerWithResponse(ctx context.Context, t *testing.T, response any) (*httptest.Server, *cloudkms.Service) {
	t.Helper()
	var b []byte
	switch r := response.(type) {
	case *cloudkms.EncryptResponse, *cloudkms.DecryptResponse:
		var err error
		b, err = json.Marshal(r)
		if err != nil {
			t.Fatalf("unable to marshal response: %v", err)
		}
	default:
		t.Fatalf("unsupported response type: %T", r)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(b)
	}))
	svc, err := cloudkms.NewService(ctx, option.WithoutAuthentication(), option.WithEndpoint(ts.URL))
	if err != nil {
		t.Fatalf("unable to create client: %v", err)
	}
	return ts, svc
}

func TestEncrypt_FailsWhenPlaintextUnverifed(t *testing.T) {
	additionalData := []byte("additional data")
	ciphertext := []byte("ciphertext")
	ciphertextCrc32c := int64(crc32.Checksum(ciphertext, crc32.MakeTable(crc32.Castagnoli)))

	testcases := []struct {
		name            string
		encryptResponse *cloudkms.EncryptResponse
	}{
		{
			name: "verified_plaintext_crc32c is false",
			encryptResponse: &cloudkms.EncryptResponse{
				Ciphertext:              base64.StdEncoding.EncodeToString(ciphertext),
				CiphertextCrc32c:        ciphertextCrc32c,
				VerifiedPlaintextCrc32c: false,
				VerifiedAdditionalAuthenticatedDataCrc32c: true,
			},
		},
		{
			name: "verified_plaintext_crc32c missing",
			encryptResponse: &cloudkms.EncryptResponse{
				Ciphertext:       base64.StdEncoding.EncodeToString(ciphertext),
				CiphertextCrc32c: ciphertextCrc32c,
				VerifiedAdditionalAuthenticatedDataCrc32c: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ts, svc := initializeServerWithResponse(ctx, t, tc.encryptResponse)
			defer ts.Close()

			aead := newGCPAEAD("key name", svc)
			// Encryption should fail for all plaintexts (empty or non-empty)
			_, err := aead.Encrypt([]byte("plaintext"), additionalData)
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
			_, err = aead.Encrypt([]byte(""), additionalData)
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
		})
	}
}

func TestEncrypt_FailsWhenAdditionalAuthenticatedDataUnverifed(t *testing.T) {
	plaintext := []byte("plaintext")
	ciphertext := []byte("ciphertext")
	ciphertextCrc32c := int64(crc32.Checksum(ciphertext, crc32.MakeTable(crc32.Castagnoli)))

	testcases := []struct {
		name            string
		encryptResponse *cloudkms.EncryptResponse
	}{
		{
			name: "verified_additional_authenticated_data_crc32c is false",
			encryptResponse: &cloudkms.EncryptResponse{
				Ciphertext:              base64.StdEncoding.EncodeToString(ciphertext),
				CiphertextCrc32c:        ciphertextCrc32c,
				VerifiedPlaintextCrc32c: true,
				VerifiedAdditionalAuthenticatedDataCrc32c: false,
			},
		},
		{
			name: "verified_additional_authenticated_data_crc32c missing",
			encryptResponse: &cloudkms.EncryptResponse{
				Ciphertext:              base64.StdEncoding.EncodeToString(ciphertext),
				CiphertextCrc32c:        ciphertextCrc32c,
				VerifiedPlaintextCrc32c: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ts, svc := initializeServerWithResponse(ctx, t, tc.encryptResponse)
			defer ts.Close()

			aead := newGCPAEAD("key name", svc)
			// Encryption should fail for all additional authenticated data (empty or non-empty)
			_, err := aead.Encrypt(plaintext, []byte("additional data"))
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
			_, err = aead.Encrypt(plaintext, []byte(""))
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
		})
	}
}

func TestEncrypt_FailsWithInvalidCiphertextCrc32c(t *testing.T) {
	testcases := []struct {
		name            string
		encryptResponse *cloudkms.EncryptResponse
	}{
		{
			name: "ciphertext_crc32c does not match ciphertext",
			encryptResponse: &cloudkms.EncryptResponse{
				Ciphertext:              base64.StdEncoding.EncodeToString([]byte("ciphertext")),
				CiphertextCrc32c:        int64(1),
				VerifiedPlaintextCrc32c: true,
				VerifiedAdditionalAuthenticatedDataCrc32c: true,
			},
		},
		{
			name: "ciphertext_crc32c missing",
			encryptResponse: &cloudkms.EncryptResponse{
				Ciphertext:              base64.StdEncoding.EncodeToString([]byte("ciphertext")),
				VerifiedPlaintextCrc32c: true,
				VerifiedAdditionalAuthenticatedDataCrc32c: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ts, svc := initializeServerWithResponse(ctx, t,
				tc.encryptResponse)
			defer ts.Close()

			aead := newGCPAEAD("key name", svc)
			_, err := aead.Encrypt([]byte("plaintext"), []byte("additional data"))
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
		})
	}
}

func TestEncrypt_Success(t *testing.T) {
	ciphertext := []byte("ciphertext")
	ciphertextCrc32c := int64(crc32.Checksum(ciphertext, crc32.MakeTable(crc32.Castagnoli)))

	ctx := context.Background()
	ts, svc := initializeServerWithResponse(ctx, t,
		&cloudkms.EncryptResponse{
			Ciphertext:              base64.StdEncoding.EncodeToString(ciphertext),
			CiphertextCrc32c:        ciphertextCrc32c,
			VerifiedPlaintextCrc32c: true,
			VerifiedAdditionalAuthenticatedDataCrc32c: true,
		})
	defer ts.Close()

	aead := newGCPAEAD("key name", svc)
	gotCiphertext, err := aead.Encrypt([]byte("plaintext"), []byte("additional data"))
	if err != nil {
		t.Errorf("a.Encrypt err = %q, want nil", err)
	}
	if !bytes.Equal(gotCiphertext, ciphertext) {
		t.Errorf("Returned ciphertext: %q, want: %q", gotCiphertext, ciphertext)
	}
}

func TestDecrypt_FailsWithInvalidPlaintextCrc32c(t *testing.T) {
	testcases := []struct {
		name            string
		decryptResponse *cloudkms.DecryptResponse
	}{
		{
			name: "plaintext_crc32c does not match plaintext",
			decryptResponse: &cloudkms.DecryptResponse{
				Plaintext:       base64.StdEncoding.EncodeToString([]byte("plaintext")),
				PlaintextCrc32c: int64(1),
			},
		},
		{
			name: "plaintext_crc32c missing",
			decryptResponse: &cloudkms.DecryptResponse{
				Plaintext: base64.StdEncoding.EncodeToString([]byte("plaintext")),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ts, svc := initializeServerWithResponse(ctx, t,
				tc.decryptResponse)
			defer ts.Close()

			aead := newGCPAEAD("key name", svc)
			_, err := aead.Decrypt([]byte("ciphertext"), []byte("additional data"))
			if err == nil {
				t.Errorf("a.Decrypt err = nil, want error")
			}
		})
	}
}

func TestDecrypt_Success(t *testing.T) {
	plaintext := []byte("plaintext")
	plaintextCrc32c := int64(crc32.Checksum(plaintext, crc32.MakeTable(crc32.Castagnoli)))

	ctx := context.Background()
	ts, svc := initializeServerWithResponse(ctx, t,
		&cloudkms.DecryptResponse{
			Plaintext:       base64.StdEncoding.EncodeToString(plaintext),
			PlaintextCrc32c: plaintextCrc32c,
		})
	defer ts.Close()

	aead := newGCPAEAD("key name", svc)
	gotPlaintext, err := aead.Decrypt([]byte("ciphertext"), []byte("additional data"))
	if err != nil {
		t.Errorf("a.Decrypt err = %q, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("Returned plaitext: %q, want: %q", gotPlaintext, plaintext)
	}
}
