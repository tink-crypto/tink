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

package internal_test

import (
	"testing"

	"github.com/google/tink/go/signature/internal"
)

func TestValidatePublicExponent(t *testing.T) {
	if err := internal.RSAValidPublicExponent(65537); err != nil {
		t.Errorf("ValidPublicExponent(65537) err = %v, want nil", err)
	}
}

func TestValidateInvalidPublicExponentFails(t *testing.T) {
	if err := internal.RSAValidPublicExponent(3); err == nil {
		t.Errorf("ValidPublicExponent(3) err = nil, want error")
	}
}

func TestValidateModulusSizeInBits(t *testing.T) {
	if err := internal.RSAValidModulusSizeInBits(2048); err != nil {
		t.Errorf("ValidModulusSizeInBits(2048) err = %v, want nil", err)
	}
}

func TestValidateInvalidModulusSizeInBitsFails(t *testing.T) {
	if err := internal.RSAValidModulusSizeInBits(1024); err == nil {
		t.Errorf("ValidModulusSizeInBits(1024) err = nil, want error")
	}
}

func TestHashSafeForSignature(t *testing.T) {
	for _, h := range []string{
		"SHA256",
		"SHA384",
		"SHA512",
	} {
		t.Run(h, func(t *testing.T) {
			if err := internal.HashSafeForSignature(h); err != nil {
				t.Errorf("HashSafeForSignature(%q)  err = %v, want nil", h, err)
			}
		})
	}
}

func TestHashNotSafeForSignatureFails(t *testing.T) {
	for _, h := range []string{
		"SHA1",
		"SHA224",
		"MD5",
	} {
		t.Run(h, func(t *testing.T) {
			if err := internal.HashSafeForSignature(h); err == nil {
				t.Errorf("HashSafeForSignature(%q)  err = nil, want error", h)
			}
		})
	}
}
