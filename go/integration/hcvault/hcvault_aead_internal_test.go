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
//
////////////////////////////////////////////////////////////////////////////////

package hcvault

import (
	"testing"
)

func TestGetEndpointPaths(t *testing.T) {
	for _, tc := range []struct {
		desc string
		uri  string
		enc  string
		dec  string
		err  string
	}{
		{
			desc: "simple",
			uri:  "hcvault://vault.example.com/transit/keys/foo",
			enc:  "transit/encrypt/foo",
			dec:  "transit/decrypt/foo",
		},
		{
			desc: "escaped",
			uri:  "hcvault://vault.example.com/transit/keys/this%2Band+that",
			enc:  "transit/encrypt/this%2Band+that",
			dec:  "transit/decrypt/this%2Band+that",
		},
		{
			desc: "sub-path",
			uri:  "hcvault://vault.example.com/teams/billing/something/transit/keys/pci-key",
			enc:  "teams/billing/something/transit/encrypt/pci-key",
			dec:  "teams/billing/something/transit/decrypt/pci-key",
		},
		{
			desc: "transit-twice",
			uri:  "hcvault://vault.example.com/transit/keys/something/transit/keys/my-key",
			enc:  "transit/keys/something/transit/encrypt/my-key",
			dec:  "transit/keys/something/transit/decrypt/my-key",
		},
		{
			desc: "hyphen-host",
			uri:  "hcvault://vault-prd.example.com/transit/keys/hi",
			enc:  "transit/encrypt/hi",
			dec:  "transit/decrypt/hi",
		},
		{
			desc: "no-host",
			uri:  "hcvault:///transit/keys/hi",
			enc:  "transit/encrypt/hi",
			dec:  "transit/decrypt/hi",
		},
		{
			desc: "mount-not-named-transit",
			uri:  "hcvault:///cipher/keys/hi",
			enc:  "cipher/encrypt/hi",
			dec:  "cipher/decrypt/hi",
		},
		{
			desc: "http",
			uri:  "http://vault.com/hi",
			err:  "malformed keyURL",
		},
		{
			desc: "no-path",
			uri:  "hcvault://vault.com",
			err:  "malformed keyURL",
		},
		{
			desc: "slash-only",
			uri:  "hcvault://vault.com/",
			err:  "malformed keyURL",
		},
		{
			desc: "not-transit",
			uri:  "hcvault://vault.example.com/foo/bar/baz",
			err:  "malformed keyURL",
		},
		{
			desc: "not-end-of-path",
			uri:  "hcvault://vault.example.com/transit/keys/bar/baz",
			err:  "malformed keyURL",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			encPath, decPath, err := getEndpointPaths(tc.uri)
			if err == nil {
				if tc.err != "" {
					t.Errorf("getEndpointPaths(%q) err is nil, want %q", tc.uri, tc.err)
				}
			} else {
				if tc.err != err.Error() {
					t.Errorf("getEndpointPaths(%q) err = %v; want %q", tc.uri, err, tc.err)
				}
			}

			if encPath != tc.enc {
				t.Errorf("getEndpointPaths(%q) encryptPath = %q, want %q", tc.uri, encPath, tc.enc)
			}
			if decPath != tc.dec {
				t.Errorf("getEndpointPaths(%q) decryptPath = %q, want %q", tc.uri, decPath, tc.dec)
			}
		})
	}
}
