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
