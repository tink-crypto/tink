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

package tink

import (
	"fmt"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// Entry represents a single entry in the keyset. In addition to the actual primitive,
// it holds the identifier and status of the primitive.
type Entry struct {
	primitive        interface{}
	identifier       string
	status           tinkpb.KeyStatusType
	outputPrefixType tinkpb.OutputPrefixType
}

// NewEntry creates a new instance of Entry using the given information.
func NewEntry(p interface{}, id string, stt tinkpb.KeyStatusType,
	outputPrefixType tinkpb.OutputPrefixType) *Entry {
	return &Entry{
		primitive:        p,
		identifier:       id,
		status:           stt,
		outputPrefixType: outputPrefixType,
	}
}

func (e *Entry) Primitive() interface{} {
	return e.primitive
}

func (e *Entry) Status() tinkpb.KeyStatusType {
	return e.status
}

func (e *Entry) Identifier() string {
	return e.identifier
}

func (e *Entry) OutputPrefixType() tinkpb.OutputPrefixType {
	return e.outputPrefixType
}

/**
 * A container class for a set of primitives (i.e. implementations of cryptographic
 * primitives offered by Tink).  It provides also additional properties for the primitives
 * it holds.  In particular, one of the primitives in the set can be distinguished as
 * "the primary" one. <p>
 *
 * PrimitiveSet is an auxiliary class used for supporting key rotation: primitives in a set
 * correspond to keys in a keyset.  Users will usually work with primitive instances,
 * which essentially wrap primitive sets.  For example an instance of an Aead-primitive
 * for a given keyset holds a set of Aead-primitives corresponding to the keys in the keyset,
 * and uses the set members to do the actual crypto operations: to encrypt data the primary
 * Aead-primitive from the set is used, and upon decryption the ciphertext's prefix
 * determines the id of the primitive from the set. <p>
 *
 * PrimitiveSet is a public class to allow its use in implementations of custom primitives.
 */
type PrimitiveSet struct {
	// Primary entry
	primary *Entry

	// The primitives are stored in a map of
	// (ciphertext prefix, list of primitives sharing the prefix).
	// This allows quickly retrieving the primitives sharing some particular prefix.
	// Because all RAW keys are using an empty prefix, this also quickly allows retrieving them.
	primitives map[string][]*Entry
}

// NewPrimitiveSet returns an empty instance of PrimitiveSet.
func NewPrimitiveSet() *PrimitiveSet {
	return &PrimitiveSet{
		primary:    nil,
		primitives: make(map[string][]*Entry),
	}
}

// GetRawPrimitives returns all primitives in the set that have RAW prefix.
func (ps *PrimitiveSet) GetRawPrimitives() ([]*Entry, error) {
	return ps.GetPrimitivesWithStringIdentifier(RAW_PREFIX)
}

// GetPrimitivesWithKey returns all primitives in the set that have prefix equal
// to that of the given key.
func (ps *PrimitiveSet) GetPrimitivesWithKey(key *tinkpb.Keyset_Key) ([]*Entry, error) {
	if key == nil {
		return nil, fmt.Errorf("primitive_set: key must not be nil")
	}
	id, err := GetOutputPrefix(key)
	if err != nil {
		return nil, fmt.Errorf("primitive_set: %s", err)
	}
	return ps.GetPrimitivesWithStringIdentifier(id)
}

// GetPrimitivesWithByteIdentifier returns all primitives in the set that have
// the given prefix.
func (ps *PrimitiveSet) GetPrimitivesWithByteIdentifier(id []byte) ([]*Entry, error) {
	return ps.GetPrimitivesWithStringIdentifier(string(id))
}

// GetPrimitivesWithStringIdentifier returns all primitives in the set that have
// the given prefix.
func (ps *PrimitiveSet) GetPrimitivesWithStringIdentifier(id string) ([]*Entry, error) {
	result, found := ps.primitives[id]
	if !found {
		return []*Entry{}, nil
	}
	return result, nil
}

// GetPrimitives returns all primitives of the set.
func (ps *PrimitiveSet) Primitives() map[string][]*Entry {
	return ps.primitives
}

// Primary returns the entry with the primary primitive.
func (ps *PrimitiveSet) Primary() *Entry {
	return ps.primary
}

// SetPrimary sets the primary entry of the set to the given entry.
func (ps *PrimitiveSet) SetPrimary(e *Entry) {
	ps.primary = e
}

// AddPrimitive creates a new entry in the primitive set using the given information
// and returns the added entry.
func (ps *PrimitiveSet) AddPrimitive(primitive interface{},
	key *tinkpb.Keyset_Key) (*Entry, error) {
	if key == nil || primitive == nil {
		return nil, fmt.Errorf("primitive_set: key and primitive must not be nil")
	}
	id, err := GetOutputPrefix(key)
	if err != nil {
		return nil, fmt.Errorf("primitive_set: %s", err)
	}
	e := NewEntry(primitive, id, key.Status, key.OutputPrefixType)
	ps.primitives[id] = append(ps.primitives[id], e)
	return e, nil
}
