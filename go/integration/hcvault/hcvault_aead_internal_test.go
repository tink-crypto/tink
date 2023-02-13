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

func TestExtractKey(t *testing.T) {
	for _, tc := range []struct {
		desc string
		uri  string
		key  string
		err  string
	}{
		{
			desc: "simple",
			uri:  "hcvault://vault.example.com/hi",
			key:  "hi",
		},
		{
			desc: "path",
			uri:  "hcvault://vault.example.com/foo/bar/baz",
			key:  "foo/bar/baz",
		},
		{
			desc: "hyphen host",
			uri:  "hcvault://vault-prd.example.com/coyote",
			key:  "coyote",
		},
		{
			desc: "empty string",
			uri:  "hcvault://example.com/",
			key:  "",
		},
		{
			desc: "escaped",
			uri:  "hcvault://vault.example.com/this%2Band+that",
			key:  "this%2Band+that",
		},
		{
			desc: "no host",
			uri:  "hcvault:///hi",
			key:  "hi",
		},
		{
			desc: "http",
			uri:  "http://vault.com/hi",
			err:  "malformed keyURL",
		},
		{
			desc: "no path",
			uri:  "hcvault://vault.com",
			err:  "malformed keyURL",
		},
		{
			desc: "slash only",
			uri:  "hcvault://vault.com/",
			key:  "",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			key, err := (&vaultAEAD{}).extractKey(tc.uri)
			if err == nil {
				if tc.err != "" {
					t.Fatalf("Missing error, want=%s", tc.err)
				}
			} else {
				if tc.err != err.Error() {
					t.Fatalf("Incorrect error, want=%s;got=%s", tc.err, err)
				}
			}
			if key != tc.key {
				t.Fatalf("Incorrect key, want=%s;got=%s", tc.key, key)
			}
		})
	}
}
