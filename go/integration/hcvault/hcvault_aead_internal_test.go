// Copyright 2023 Google LLC
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

package hcvault

import (
	"bytes"
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestGetEndpointPaths(t *testing.T) {
	for _, tc := range []struct {
		desc string
		path string
		enc  string
		dec  string
		err  string
	}{
		{
			desc: "simple",
			path: "/transit/keys/foo",
			enc:  "transit/encrypt/foo",
			dec:  "transit/decrypt/foo",
		},
		{
			desc: "escaped",
			path: "/transit/keys/this%2Band+that",
			enc:  "transit/encrypt/this%2Band+that",
			dec:  "transit/decrypt/this%2Band+that",
		},
		{
			desc: "sub-path",
			path: "/teams/billing/something/transit/keys/pci-key",
			enc:  "teams/billing/something/transit/encrypt/pci-key",
			dec:  "teams/billing/something/transit/decrypt/pci-key",
		},
		{
			desc: "transit-twice",
			path: "/transit/keys/something/transit/keys/my-key",
			enc:  "transit/keys/something/transit/encrypt/my-key",
			dec:  "transit/keys/something/transit/decrypt/my-key",
		},
		{
			desc: "mount-not-named-transit",
			path: "/cipher/keys/hi",
			enc:  "cipher/encrypt/hi",
			dec:  "cipher/decrypt/hi",
		},
		{
			desc: "no leading slash",
			path: "transit/keys/foo",
			err:  "malformed keyPath",
		},
		{
			desc: "empty",
			path: "",
			err:  "malformed keyPath",
		},
		{
			desc: "slash-only",
			path: "/",
			err:  "malformed keyPath",
		},
		{
			desc: "not-transit",
			path: "/foo/bar/baz",
			err:  "malformed keyPath",
		},
		{
			desc: "not-end-of-path",
			path: "/transit/keys/bar/baz",
			err:  "malformed keyPath",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			encPath, decPath, err := getEndpointPaths(tc.path)
			if err == nil {
				if tc.err != "" {
					t.Errorf("getEndpointPaths(%q) err is nil, want %q", tc.path, tc.err)
				}
			} else {
				if tc.err != err.Error() {
					t.Errorf("getEndpointPaths(%q) err = %v; want %q", tc.path, err, tc.err)
				}
			}

			if encPath != tc.enc {
				t.Errorf("getEndpointPaths(%q) encryptPath = %q, want %q", tc.path, encPath, tc.enc)
			}
			if decPath != tc.dec {
				t.Errorf("getEndpointPaths(%q) decryptPath = %q, want %q", tc.path, decPath, tc.dec)
			}
		})
	}
}

func TestExtractCiphertextFails(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		secret *api.Secret
	}{
		{
			desc:   "nil",
			secret: nil,
		},
		{
			desc: "empty data",
			secret: &api.Secret{
				Data: map[string]any{},
			},
		},
		{
			desc: "empty ciphertext",
			secret: &api.Secret{
				Data: map[string]any{"ciphertext": ""},
			},
		},
		{
			desc: "wrong type",
			secret: &api.Secret{
				Data: map[string]any{"ciphertext": 123},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := extractCiphertext(tc.secret)
			if err == nil {
				t.Error("extractCiphertext() err is nil, want error")
			}
		})
	}
}

func TestExtractCiphertextWorks(t *testing.T) {
	secret := &api.Secret{
		Data: map[string]any{"ciphertext": "ciphertext"},
	}
	got, err := extractCiphertext(secret)
	if err != nil {
		t.Fatalf("extractCiphertext() err = %q, want nil", err)
	}
	want := []byte("ciphertext")
	if !bytes.Equal(got, want) {
		t.Errorf("extractCiphertext() = %q, want %q", got, want)
	}
}

func TestExtractPlaintextFails(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		secret *api.Secret
	}{
		{
			desc: "wrong type",
			secret: &api.Secret{
				Data: map[string]any{"plaintext": 123},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := extractPlaintext(tc.secret)
			if err == nil {
				t.Error("extractPlaintext() err is nil, want error")
			}
		})
	}
}

func TestExtractPlaintextWorks(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		secret *api.Secret
		want   []byte
	}{
		{
			desc: "normal",
			secret: &api.Secret{
				Data: map[string]any{"plaintext": "cGxhaW50ZXh0"},
			},
			want: []byte("plaintext"),
		},
		{
			desc: "empty plaintext",
			secret: &api.Secret{
				Data: map[string]any{"plaintext": ""},
			},
			want: []byte{},
		},
		{
			desc: "empty data",
			secret: &api.Secret{
				Data: map[string]any{},
			},
			want: []byte{},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := extractPlaintext(tc.secret)
			if err != nil {
				t.Fatalf("extractPlaintext() err = %q, want nil", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("extractPlaintext() = %q, want %q", got, tc.want)
			}
		})
	}
}
