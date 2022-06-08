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

package monitoringutil_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/internal/monitoringutil"
	"github.com/google/tink/go/monitoring"
	tpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestKeysetInfoFromPrimitiveSetWithNilPrimitiveSetFails(t *testing.T) {
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(nil); err == nil {
		t.Errorf("KeysetInfoFromPrimitiveSet(nil) err = nil, want error")
	}
}

func validPrimitiveSet() *primitiveset.PrimitiveSet {
	return &primitiveset.PrimitiveSet{
		Primary: &primitiveset.Entry{},
		Entries: map[string][]*primitiveset.Entry{
			"one": []*primitiveset.Entry{
				{
					Status: tpb.KeyStatusType_ENABLED,
				},
			},
		},
	}
}

func TestBaselinePrimitiveSet(t *testing.T) {
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(validPrimitiveSet()); err != nil {
		t.Errorf("KeysetInfoFromPrimitiveSet() err = %v, want nil", err)
	}
}

func TestKeysetInfoFromPrimitiveSetWithNoEntryFails(t *testing.T) {
	ps := validPrimitiveSet()
	ps.Entries = nil
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps); err == nil {
		t.Errorf("KeysetInfoFromPrimitiveSet() err = nil, want error")
	}
}

func TestKeysetInfoFromPrimitiveSetWithNoPrimaryFails(t *testing.T) {
	ps := validPrimitiveSet()
	ps.Primary = nil
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps); err == nil {
		t.Errorf("KeysetInfoFromPrimitiveSet() err = nil, want error")
	}
}

func TestKeysetInfoFromPrimitiveSetWithInvalidKeyStatusFails(t *testing.T) {
	ps := validPrimitiveSet()
	ps.Entries["invalid_key_status"] = []*primitiveset.Entry{
		{
			KeyID:  123,
			Status: tpb.KeyStatusType_UNKNOWN_STATUS,
		},
	}
	if _, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps); err == nil {
		t.Errorf("KeysetInfoFromPrimitiveSet() err = nil, want error")
	}
}

func TestKeysetInfoFromPrimitiveSet(t *testing.T) {
	ps := &primitiveset.PrimitiveSet{
		Primary: &primitiveset.Entry{
			KeyID: 1,
		},
		Entries: map[string][]*primitiveset.Entry{
			// Adding all entries under the same prefix to get deterministic output.
			"one": []*primitiveset.Entry{
				&primitiveset.Entry{
					KeyID:  1,
					Status: tpb.KeyStatusType_ENABLED,
				},
				&primitiveset.Entry{
					KeyID:  2,
					Status: tpb.KeyStatusType_DISABLED,
				},
				&primitiveset.Entry{
					KeyID:  3,
					Status: tpb.KeyStatusType_DESTROYED,
				},
			},
		},
	}
	want := &monitoring.KeysetInfo{
		PrimaryKeyID: 1,
		Annotations:  make(map[string]string),
		Entries: []*monitoring.Entry{
			{
				KeyID:          1,
				Status:         monitoring.Enabled,
				FormatAsString: "",
			},
			{
				KeyID:          2,
				Status:         monitoring.Disabled,
				FormatAsString: "",
			},
			{
				KeyID:          3,
				Status:         monitoring.Destroyed,
				FormatAsString: "",
			},
		},
	}
	got, err := monitoringutil.KeysetInfoFromPrimitiveSet(ps)
	if err != nil {
		t.Fatalf("KeysetInfoFromPrimitiveSet() err = %v, want nil", err)
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v, with diff: %v", got, want, cmp.Diff(got, want))
	}
}
