// Copyright 2017 Google Inc.
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
package tink_test

import (
  "fmt"
  "testing"
  "reflect"
  "github.com/google/tink/go/util/testutil"
  "github.com/google/tink/go/tink/tink"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

func genKeysForPrimitiveSetTest() []*tinkpb.Keyset_Key {
  var keyId0 = 1234543
  var keyId1 = 7213743
  var keyId2 = keyId1
  var keyId3 = 947327
  var keyId4 = 529472
  var keyId5 = keyId0
  return []*tinkpb.Keyset_Key{
    testutil.NewDummyKey(keyId0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
    testutil.NewDummyKey(keyId1, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_LEGACY),
    testutil.NewDummyKey(keyId2, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK),
    testutil.NewDummyKey(keyId3, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_RAW),
    testutil.NewDummyKey(keyId4, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_RAW),
    testutil.NewDummyKey(keyId5, tinkpb.KeyStatusType_DISABLED, tinkpb.OutputPrefixType_TINK),
  }
}

func TestPrimitiveSetBasic(t *testing.T) {
  var err error
  ps := tink.NewPrimitiveSet()
  if ps.Primary() != nil || ps.Primitives() == nil {
    t.Errorf("expect primary to be nil and primitives is initialized")
  }
  // generate test keys
  keys := genKeysForPrimitiveSetTest()
  // add all test primitives
  macs := make([]testutil.DummyMac, len(keys))
  entries := make([]*tink.Entry, len(macs))
  for i := 0; i < len(macs); i++ {
    macs[i] = testutil.DummyMac{Name: fmt.Sprintf("Mac#%d", i)}
    entries[i], err = ps.AddPrimitive(macs[i], keys[i])
    if err != nil {
      t.Errorf("unexpected error when adding mac%d: %s", i, err)
    }
  }
  // set primary entry
  primaryId := 2
  ps.SetPrimary(entries[primaryId])
  // validate the primitive in primary
  if !validateEntry(ps.Primary(), macs[primaryId], keys[primaryId].Status, keys[primaryId].OutputPrefixType) {
    t.Errorf("SetPrimary is not working correctly")
  }
  // check raw primitive
  rawMacs := []testutil.DummyMac{macs[3], macs[4]}
  rawStatuses := []tinkpb.KeyStatusType{keys[3].Status, keys[4].Status}
  rawPrefixTypes := []tinkpb.OutputPrefixType{keys[3].OutputPrefixType, keys[4].OutputPrefixType}
  rawEntries, err := ps.GetRawPrimitives()
  if err != nil {
    t.Errorf("unexpected error when getting raw primitives: %s", err)
  }
  if !validateEntryList(rawEntries, rawMacs, rawStatuses, rawPrefixTypes) {
    t.Errorf("raw primitives do not match input")
  }
  // check tink primitives, same id
  tinkMacs := []testutil.DummyMac{macs[0], macs[5]}
  tinkStatuses := []tinkpb.KeyStatusType{keys[0].Status, keys[5].Status}
  tinkPrefixTypes := []tinkpb.OutputPrefixType{keys[0].OutputPrefixType, keys[5].OutputPrefixType}
  tinkEntries, err := ps.GetPrimitivesWithKey(keys[0])
  if err != nil {
    t.Errorf("unexpected error when getting primitives: %s", err)
  }
  if !validateEntryList(tinkEntries, tinkMacs, tinkStatuses, tinkPrefixTypes) {
    t.Errorf("tink primitives do not match the input key")
  }
  // check another tink primitive
  tinkMacs = []testutil.DummyMac{macs[2]}
  tinkStatuses = []tinkpb.KeyStatusType{keys[2].Status}
  tinkPrefixTypes = []tinkpb.OutputPrefixType{keys[2].OutputPrefixType}
  tinkEntries, err = ps.GetPrimitivesWithKey(keys[2])
  if err != nil {
    t.Errorf("unexpected error when getting tink primitives: %s", err)
  }
  if !validateEntryList(tinkEntries, tinkMacs, tinkStatuses, tinkPrefixTypes) {
    t.Errorf("tink primitives do not match the input key")
  }
  //check legacy primitives
  legacyMacs := []testutil.DummyMac{macs[1]}
  legacyStatuses := []tinkpb.KeyStatusType{keys[1].Status}
  legacyPrefixTypes := []tinkpb.OutputPrefixType{keys[1].OutputPrefixType}
  legacyPrefix, _ := tink.GetOutputPrefix(keys[1])
  legacyEntries, err := ps.GetPrimitivesWithStringIdentifier(legacyPrefix)
  if err != nil {
    t.Errorf("unexpected error when getting legacy primitives: %s", err)
  }
  if !validateEntryList(legacyEntries, legacyMacs, legacyStatuses, legacyPrefixTypes) {
    t.Errorf("legacy primitives do not match the input key")
  }
}

func TestGetPrimitivesWithInvalidInput(t *testing.T) {
  ps := tink.NewPrimitiveSet()
  if _, err := ps.GetPrimitivesWithKey(nil); err == nil {
    t.Errorf("expect an error when input is nil")
  }
}

func TestAddPrimitiveWithInvalidInput(t *testing.T) {
  ps := tink.NewPrimitiveSet()
  // nil input
  key := testutil.NewDummyKey(0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_TINK)
  if _, err := ps.AddPrimitive(nil, key); err == nil {
    t.Errorf("expect an error when primitive input is nil")
  }
  if _, err := ps.AddPrimitive(*new(testutil.DummyMac), nil); err == nil {
    t.Errorf("expect an error when key input is nil")
  }
  // unknown prefix type
  invalidKey := testutil.NewDummyKey(0, tinkpb.KeyStatusType_ENABLED, tinkpb.OutputPrefixType_UNKNOWN_PREFIX)
  if _, err := ps.AddPrimitive(*new(testutil.DummyMac), invalidKey); err == nil {
    t.Errorf("expect an error when key is invalid")
  }
}

func validateEntryList(entries []*tink.Entry,
                        macs []testutil.DummyMac,
                        statuses []tinkpb.KeyStatusType,
                        prefixTypes []tinkpb.OutputPrefixType) bool {
  if len(entries) != len(macs) {
    return false
  }
  for i := 0; i < len(entries); i++ {
    if !validateEntry(entries[i], macs[i], statuses[i], prefixTypes[i]) {
      return false
    }
  }
  return true
}

// Compares an entry with the testutil.DummyMac that was used to create the entry
func validateEntry(entry *tink.Entry,
                    testMac testutil.DummyMac,
                    status tinkpb.KeyStatusType,
                    outputPrefixType tinkpb.OutputPrefixType) bool {
  if entry.Status() != status || entry.OutputPrefixType() != outputPrefixType{
    return false
  }
  var dummyMac = entry.Primitive().(testutil.DummyMac)
  var m tink.Mac = &dummyMac
  data := []byte{1, 2, 3, 4, 5}
  digest, err := m.ComputeMac(data)
  if err != nil || !reflect.DeepEqual(append(data, testMac.Name...), digest) {
    return false
  }
  return true
}