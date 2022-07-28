// Copyright 2019 Google LLC
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

package primitiveset_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func makeTestKey(keyID int, status tinkpb.KeyStatusType, outputPrefixType tinkpb.OutputPrefixType, typeURL string) *tinkpb.Keyset_Key {
	k := testutil.NewDummyKey(keyID, status, outputPrefixType)
	k.GetKeyData().TypeUrl = typeURL
	return k
}

func TestPrimitvesetNew(t *testing.T) {
	ps := primitiveset.New()
	if ps.Primary != nil || ps.Entries == nil {
		t.Errorf("expect primary to be nil and primitives is initialized")
	}
}

func TestPrimitivesetAddEntries(t *testing.T) {
	keys := []*tinkpb.Keyset_Key{
		makeTestKey(1234543, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.1"),
		makeTestKey(7213743, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY, "type.url.2"),
		makeTestKey(5294722, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW, "type.url.3"),
	}
	macs := make([]testutil.DummyMAC, len(keys))
	for i := 0; i < len(macs); i++ {
		macs[i] = testutil.DummyMAC{Name: fmt.Sprintf("%d", i)}
	}
	ps := primitiveset.New()
	got := []*primitiveset.Entry{}
	for i := 0; i < len(macs); i++ {
		e, err := ps.Add(&macs[i], keys[i])
		if err != nil {
			t.Fatalf("ps.Add(%q) err = %v, want nil", macs[i].Name, err)
		}
		got = append(got, e)
	}
	want := []*primitiveset.Entry{
		{
			KeyID:      1234543,
			Status:     tinkpb.KeyStatusType_ENABLED,
			Primitive:  &testutil.DummyMAC{Name: "0"},
			PrefixType: tinkpb.OutputPrefixType_TINK,
			TypeURL:    "type.url.1",
			Prefix:     string([]byte{1, 0, 18, 214, 111}),
		},
		{
			KeyID:      7213743,
			Status:     tinkpb.KeyStatusType_ENABLED,
			Primitive:  &testutil.DummyMAC{Name: "1"},
			PrefixType: tinkpb.OutputPrefixType_LEGACY,
			TypeURL:    "type.url.2",
			Prefix:     string([]byte{0, 0, 110, 18, 175}),
		},
		{
			KeyID:      5294722,
			Status:     tinkpb.KeyStatusType_ENABLED,
			Primitive:  &testutil.DummyMAC{Name: "2"},
			PrefixType: tinkpb.OutputPrefixType_RAW,
			TypeURL:    "type.url.3",
			Prefix:     "",
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("got = %v, want = %v", got, want)
	}
}

func TestPrimitivesetRawEntries(t *testing.T) {
	keys := []*tinkpb.Keyset_Key{
		makeTestKey(1234543, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.1"),
		makeTestKey(7213743, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY, "type.url.2"),
		makeTestKey(9473277, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW, "type.url.3"),
		makeTestKey(5294722, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW, "type.url.4"),
	}
	macs := make([]testutil.DummyMAC, len(keys))
	for i := 0; i < len(macs); i++ {
		macs[i] = testutil.DummyMAC{Name: fmt.Sprintf("Mac#%d", i)}
	}
	ps := primitiveset.New()
	for i := 0; i < len(macs); i++ {
		if _, err := ps.Add(macs[i], keys[i]); err != nil {
			t.Fatalf("ps.Add(%q) err = %v, want nil", macs[i].Name, err)
		}
	}
	got, err := ps.RawEntries()
	if err != nil {
		t.Errorf("RawEntries() err = %v, want nil", err)
	}
	want := []*primitiveset.Entry{
		{
			KeyID:      keys[2].GetKeyId(),
			Status:     keys[2].GetStatus(),
			PrefixType: keys[2].GetOutputPrefixType(),
			TypeURL:    keys[2].GetKeyData().GetTypeUrl(),
			Primitive:  macs[2],
		},
		{
			KeyID:      keys[3].GetKeyId(),
			Status:     keys[3].GetStatus(),
			PrefixType: keys[3].GetOutputPrefixType(),
			TypeURL:    keys[3].GetKeyData().GetTypeUrl(),
			Primitive:  macs[3],
		},
	}
	if !cmp.Equal(got, want) {
		t.Errorf("Raw primitives got = %v, want = %v", got, want)
	}
}

func TestPrimitivesetPrefixedEntries(t *testing.T) {
	type testCase struct {
		tag        string
		prefix     string
		keys       []*tinkpb.Keyset_Key
		primitives []interface{}
		want       []*primitiveset.Entry
	}
	for _, tc := range []testCase{
		{
			tag:    "legacy Prefix",
			prefix: string([]byte{0, 0, 18, 214, 111}), // LEGACY_PREFIX + 1234543,
			keys: []*tinkpb.Keyset_Key{
				makeTestKey(1234543, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY, "type.url.1"),
				makeTestKey(7213743, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.2"),
			},
			primitives: []interface{}{
				&testutil.DummyMAC{Name: "1"},
				&testutil.DummyMAC{Name: "2"},
			},
			want: []*primitiveset.Entry{
				{
					KeyID:      1234543,
					Status:     tinkpb.KeyStatusType_ENABLED,
					Primitive:  &testutil.DummyMAC{Name: "1"},
					PrefixType: tinkpb.OutputPrefixType_LEGACY,
					TypeURL:    "type.url.1",
					Prefix:     string([]byte{0, 0, 18, 214, 111}),
				},
			},
		},
		{
			tag:    "raw prefix",
			prefix: "",
			keys: []*tinkpb.Keyset_Key{
				makeTestKey(1234543, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW, "type.url.1"),
				makeTestKey(7213743, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.2"),
			},
			primitives: []interface{}{
				&testutil.DummyMAC{Name: "1"},
				&testutil.DummyMAC{Name: "2"},
			},
			want: []*primitiveset.Entry{
				{
					KeyID:      1234543,
					Status:     tinkpb.KeyStatusType_ENABLED,
					Primitive:  &testutil.DummyMAC{Name: "1"},
					PrefixType: tinkpb.OutputPrefixType_RAW,
					TypeURL:    "type.url.1",
					Prefix:     "",
				},
			},
		},
		{
			tag:    "tink prefix  multiple entries",
			prefix: string([]byte{1, 0, 18, 214, 111}), // TINK_PREFIX + 1234543
			keys: []*tinkpb.Keyset_Key{
				makeTestKey(1234543, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.1"),
				makeTestKey(1234543, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.2"),
				makeTestKey(1234543, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW, "type.url.3"),
				makeTestKey(7213743, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.4"),
			},
			primitives: []interface{}{
				&testutil.DummyMAC{Name: "1"},
				&testutil.DummyMAC{Name: "2"},
				&testutil.DummyMAC{Name: "3"},
				&testutil.DummyMAC{Name: "4"},
			},
			want: []*primitiveset.Entry{
				{
					KeyID:      1234543,
					Status:     tinkpb.KeyStatusType_ENABLED,
					Primitive:  &testutil.DummyMAC{Name: "1"},
					PrefixType: tinkpb.OutputPrefixType_TINK,
					TypeURL:    "type.url.1",
					Prefix:     string([]byte{1, 0, 18, 214, 111}),
				},
				{
					KeyID:      1234543,
					Status:     tinkpb.KeyStatusType_ENABLED,
					Primitive:  &testutil.DummyMAC{Name: "2"},
					PrefixType: tinkpb.OutputPrefixType_TINK,
					TypeURL:    "type.url.2",
					Prefix:     string([]byte{1, 0, 18, 214, 111}),
				},
			},
		},
	} {
		ps := primitiveset.New()
		for i := 0; i < len(tc.keys); i++ {
			if _, err := ps.Add(tc.primitives[i], tc.keys[i]); err != nil {
				t.Fatalf("ps.Add(%q) err = %v, want nil", tc.primitives[i], err)
			}
		}
		got, err := ps.EntriesForPrefix(tc.prefix)
		if err != nil {
			t.Errorf("EntriesForPrefix() err =  %v, want nil", err)
		}
		if !cmp.Equal(got, tc.want) {
			t.Errorf("got = %v, want = %v", got, tc.want)
		}
	}
}

func TestAddWithInvalidInput(t *testing.T) {
	ps := primitiveset.New()
	type testCase struct {
		tag       string
		primitive interface{}
		key       *tinkpb.Keyset_Key
	}
	for _, tc := range []testCase{
		{
			tag:       "nil primitive",
			primitive: nil,
			key:       makeTestKey(0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK, "type.url.1"),
		},
		{
			tag:       "nil key",
			primitive: &testutil.DummyMAC{},
			key:       nil,
		},
		{
			tag:       "unknown prefix type",
			primitive: &testutil.DummyMAC{},
			key:       makeTestKey(0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_UNKNOWN_PREFIX, "type.url.1"),
		},
		{
			tag:       "disabled key",
			primitive: &testutil.DummyMAC{},
			key:       makeTestKey(0, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_TINK, "type.url.1"),
		},
		{
			tag:       "nil keyData",
			primitive: &testutil.DummyMAC{},
			key: &tinkpb.Keyset_Key{
				KeyData:          nil,
				Status:           tinkpb.KeyStatusType_ENABLED,
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            0,
			},
		},
	} {
		if _, err := ps.Add(tc.primitive, tc.key); err == nil {
			t.Errorf("Add() err = nil, want error")
		}
	}
}
