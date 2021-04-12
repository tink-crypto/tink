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

package prf_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	maxAutocorrelation = 100
)

func addKeyAndReturnID(m *keyset.Manager, template *tinkpb.KeyTemplate) (uint32, error) {
	err := m.Rotate(template)
	if err != nil {
		return 0, fmt.Errorf("Could not add template: %v", err)
	}
	h, err := m.Handle()
	if err != nil {
		return 0, fmt.Errorf("Could not obtain handle: %v", err)
	}
	p, err := h.Primitives()
	if err != nil {
		return 0, fmt.Errorf("Could not obtain primitives: %v", err)
	}
	return p.Primary.KeyID, nil
}

func TestFactoryBasic(t *testing.T) {
	manager := keyset.NewManager()
	aescmacID, err := addKeyAndReturnID(manager, prf.AESCMACPRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add AES CMAC PRF key: %v", err)
	}

	hmacsha256ID, err := addKeyAndReturnID(manager, prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add HMAC SHA256 PRF key: %v", err)
	}
	hkdfsha256ID, err := addKeyAndReturnID(manager, prf.HKDFSHA256PRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add HKDF SHA256 PRF key: %v", err)
	}
	hmacsha512ID, err := addKeyAndReturnID(manager, prf.HMACSHA512PRFKeyTemplate())
	if err != nil {
		t.Errorf("Could not add HMAC SHA512 PRF key: %v", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Errorf("Could not obtain handle: %v", err)
	}
	prfSet, err := prf.NewPRFSet(handle)
	if err != nil {
		t.Errorf("Could not create prf.Set with standard key templates: %v", err)
	}
	primaryID := prfSet.PrimaryID
	if primaryID != hmacsha512ID {
		t.Errorf("Primary ID %d should be the ID %d, which was added last", primaryID, hmacsha512ID)
	}
	for _, length := range []uint32{1, 10, 16, 17, 32, 33, 64, 65, 100, 8160, 8161} {
		results := [][]byte{}
		for id, prf := range prfSet.PRFs {
			ok := true
			switch {
			case length > 16 && id == aescmacID:
				ok = false
			case length > 32 && id == hmacsha256ID:
				ok = false
			case length > 64 && id == hmacsha512ID:
				ok = false
			case length > 8160 && id == hkdfsha256ID:
				ok = false
			}

			result1, err := prf.ComputePRF([]byte("The input"), length)
			switch {
			case err != nil && !ok:
				continue
			case err != nil:
				t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
				continue
			case !ok:
				t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
				continue
			}
			result2, err := prf.ComputePRF([]byte("The different input"), length)
			switch {
			case err != nil && !ok:
				continue
			case err != nil:
				t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
				continue
			case !ok:
				t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
				continue
			}
			result3, err := prf.ComputePRF([]byte("The input"), length)
			switch {
			case err != nil && !ok:
				continue
			case err != nil:
				t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
				continue
			case !ok:
				t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
				continue
			}
			if id == primaryID {
				primaryResult, err := prfSet.ComputePrimaryPRF([]byte("The input"), length)
				switch {
				case err != nil && !ok:
					continue
				case err != nil:
					t.Errorf("Expected to be able to compute %d bytes of PRF output: %v", length, err)
					continue
				case !ok:
					t.Errorf("Expected to be unable to compute %d bytes PRF output", length)
					continue
				}
				if hex.EncodeToString(result1) != hex.EncodeToString(primaryResult) {
					t.Errorf("Expected manual call of ComputePRF of primary PRF and ComputePrimaryPRF with the same input to produce the same output, but got %q and %q", result1, primaryResult)
				}
			}
			if hex.EncodeToString(result1) != hex.EncodeToString(result3) {
				t.Errorf("Expected different calls with the same input to produce the same output, but got %q and %q", result1, result3)
			}
			results = append(results, result1)
			results = append(results, result2)
		}
		runZTests(results, t)
	}
}

func TestNonRawKeys(t *testing.T) {
	template := prf.AESCMACPRFKeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_TINK
	h, err := keyset.NewHandle(template)
	if err != nil {
		t.Errorf("Couldn't create keyset: %v", err)
	}
	_, err = prf.NewPRFSet(h)
	if err == nil {
		t.Errorf("Expected non RAW prefix to fail to create prf.Set")
	}
	m := keyset.NewManagerFromHandle(h)
	err = m.Rotate(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Errorf("Expected to be able to add keys to the keyset: %v", err)
	}
	h, err = m.Handle()
	if err != nil {
		t.Errorf("Expected to be able to create keyset handle: %v", err)
	}
	_, err = prf.NewPRFSet(h)
	if err == nil {
		t.Errorf("Expected mixed prefix keyset to fail to create prf.Set")
	}
}

func TestNonPRFPrimitives(t *testing.T) {
	template := mac.AESCMACTag128KeyTemplate()
	template.OutputPrefixType = tinkpb.OutputPrefixType_RAW
	h, err := keyset.NewHandle(template)
	if err != nil {
		t.Errorf("Couldn't create keyset: %v", err)
	}
	_, err = prf.NewPRFSet(h)
	if err == nil {
		t.Errorf("Expected non PRF primitive to fail to create prf.Set")
	}
	m := keyset.NewManagerFromHandle(h)
	err = m.Rotate(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Errorf("Expected to be able to add keys to the keyset: %v", err)
	}
	h, err = m.Handle()
	if err != nil {
		t.Errorf("Expected to be able to create keyset handle: %v", err)
	}
	_, err = prf.NewPRFSet(h)
	if err == nil {
		t.Errorf("Expected mixed primitive keyset to fail to create prf.Set")
	}
}

func runZTests(results [][]byte, t *testing.T) {
	for i, result1 := range results {
		if err := testutil.ZTestUniformString(result1); err != nil {
			t.Errorf("Expected PRF output to pass uniformity z test: %v", err)
		}
		if len(result1) <= maxAutocorrelation {
			if err := testutil.ZTestAutocorrelationUniformString(result1); err != nil {
				t.Errorf("Expected PRF output to pass autocorrelation test: %v", err)
			}
		}
		for j := i + 1; j < len(results); j++ {
			result2 := results[j]
			if err := testutil.ZTestCrosscorrelationUniformStrings(result1, result2); err != nil {
				t.Errorf("Expected different PRF outputs to be uncorrelated: %v", err)
			}
		}
	}
}
