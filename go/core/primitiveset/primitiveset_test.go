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
	"reflect"
	"testing"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func createKeyset() []*tinkpb.Keyset_Key {
	var keyID0 = 1234543
	var keyID1 = 7213743
	var keyID2 = keyID1
	var keyID3 = 947327
	var keyID4 = 529472
	var keyID5 = keyID0
	return []*tinkpb.Keyset_Key{
		testutil.NewDummyKey(keyID0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(keyID1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY),
		testutil.NewDummyKey(keyID2, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
		testutil.NewDummyKey(keyID3, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW),
		testutil.NewDummyKey(keyID4, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW),
		testutil.NewDummyKey(keyID5, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
	}
}

func TestPrimitiveSetBasic(t *testing.T) {
	var err error
	ps := primitiveset.New()
	if ps.Primary != nil || ps.Entries == nil {
		t.Errorf("expect primary to be nil and primitives is initialized")
	}
	// generate test keys
	keys := createKeyset()
	// add all test primitives
	macs := make([]testutil.DummyMAC, len(keys))
	entries := make([]*primitiveset.Entry, len(macs))
	for i := 0; i < len(macs); i++ {
		macs[i] = testutil.DummyMAC{Name: fmt.Sprintf("Mac#%d", i)}
		entries[i], err = ps.Add(macs[i], keys[i])
		if err != nil {
			t.Errorf("unexpected error when adding mac%d: %s", i, err)
		}
	}
	// set primary entry
	primaryID := 2
	ps.Primary = entries[primaryID]

	// check raw primitive
	rawIDs := []uint32{keys[3].GetKeyId(), keys[4].GetKeyId()}
	rawMacs := []testutil.DummyMAC{macs[3], macs[4]}
	rawStatuses := []tinkpb.KeyStatusType{keys[3].Status, keys[4].Status}
	rawPrefixTypes := []tinkpb.OutputPrefixType{keys[3].OutputPrefixType, keys[4].OutputPrefixType}
	rawEntries, err := ps.RawEntries()
	if err != nil {
		t.Errorf("unexpected error when getting raw primitives: %s", err)
	}
	if !validateEntryList(rawEntries, rawIDs, rawMacs, rawStatuses, rawPrefixTypes) {
		t.Errorf("raw primitives do not match input")
	}
	// check tink primitives, same id
	tinkIDs := []uint32{keys[0].GetKeyId(), keys[5].GetKeyId()}
	tinkMacs := []testutil.DummyMAC{macs[0], macs[5]}
	tinkStatuses := []tinkpb.KeyStatusType{keys[0].Status, keys[5].Status}
	tinkPrefixTypes := []tinkpb.OutputPrefixType{keys[0].OutputPrefixType, keys[5].OutputPrefixType}
	prefix, _ := cryptofmt.OutputPrefix(keys[0])
	tinkEntries, err := ps.EntriesForPrefix(prefix)
	if err != nil {
		t.Errorf("unexpected error when getting primitives: %s", err)
	}
	if !validateEntryList(tinkEntries, tinkIDs, tinkMacs, tinkStatuses, tinkPrefixTypes) {
		t.Errorf("tink primitives do not match the input key")
	}
	// check another tink primitive
	tinkIDs = []uint32{keys[2].GetKeyId()}
	tinkMacs = []testutil.DummyMAC{macs[2]}
	tinkStatuses = []tinkpb.KeyStatusType{keys[2].Status}
	tinkPrefixTypes = []tinkpb.OutputPrefixType{keys[2].OutputPrefixType}
	prefix, _ = cryptofmt.OutputPrefix(keys[2])
	tinkEntries, err = ps.EntriesForPrefix(prefix)
	if err != nil {
		t.Errorf("unexpected error when getting tink primitives: %s", err)
	}
	if !validateEntryList(tinkEntries, tinkIDs, tinkMacs, tinkStatuses, tinkPrefixTypes) {
		t.Errorf("tink primitives do not match the input key")
	}
	//check legacy primitives
	legacyIDs := []uint32{keys[1].GetKeyId()}
	legacyMacs := []testutil.DummyMAC{macs[1]}
	legacyStatuses := []tinkpb.KeyStatusType{keys[1].Status}
	legacyPrefixTypes := []tinkpb.OutputPrefixType{keys[1].OutputPrefixType}
	legacyPrefix, _ := cryptofmt.OutputPrefix(keys[1])
	legacyEntries, err := ps.EntriesForPrefix(legacyPrefix)
	if err != nil {
		t.Errorf("unexpected error when getting legacy primitives: %s", err)
	}
	if !validateEntryList(legacyEntries, legacyIDs, legacyMacs, legacyStatuses, legacyPrefixTypes) {
		t.Errorf("legacy primitives do not match the input key")
	}
}

func TestAddWithInvalidInput(t *testing.T) {
	ps := primitiveset.New()
	// nil input
	key := testutil.NewDummyKey(0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK)
	if _, err := ps.Add(nil, key); err == nil {
		t.Errorf("expect an error when primitive input is nil")
	}
	if _, err := ps.Add(*new(testutil.DummyMAC), nil); err == nil {
		t.Errorf("expect an error when key input is nil")
	}
	// unknown prefix type
	invalidKey := testutil.NewDummyKey(0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_UNKNOWN_PREFIX)
	if _, err := ps.Add(*new(testutil.DummyMAC), invalidKey); err == nil {
		t.Errorf("expect an error when key is invalid")
	}
	// disabled key
	disabledKey := testutil.NewDummyKey(0, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_UNKNOWN_PREFIX)
	if _, err := ps.Add(*new(testutil.DummyMAC), disabledKey); err == nil {
		t.Errorf("expect an error when key is disabled")
	}

}

func validateEntryList(entries []*primitiveset.Entry,
	keyIDs []uint32,
	macs []testutil.DummyMAC,
	statuses []tinkpb.KeyStatusType,
	prefixTypes []tinkpb.OutputPrefixType) bool {
	if len(entries) != len(macs) {
		return false
	}
	for i := 0; i < len(entries); i++ {
		if !validateEntry(entries[i], keyIDs[i], macs[i], statuses[i], prefixTypes[i]) {
			return false
		}
	}
	return true
}

// Compares an entry with the testutil.DummyMAC that was used to create the entry
func validateEntry(entry *primitiveset.Entry,
	keyID uint32,
	testMac testutil.DummyMAC,
	status tinkpb.KeyStatusType,
	outputPrefixType tinkpb.OutputPrefixType) bool {
	if entry.KeyID != keyID || entry.Status != status || entry.PrefixType != outputPrefixType {
		return false
	}
	var dummyMac = entry.Primitive.(testutil.DummyMAC)
	data := []byte{1, 2, 3, 4, 5}
	digest, err := dummyMac.ComputeMAC(data)
	if err != nil || !reflect.DeepEqual(append(data, testMac.Name...), digest) {
		return false
	}
	return true
}
