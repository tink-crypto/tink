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

// Package monitoring defines the structs and interfaces for monitoring primitives with Tink.
// This package isn't yet production ready and might go through various changes.
package monitoring

// KeyStatus represents KeyStatusType in tink/proto/tink.proto.
type KeyStatus int

const (
	// Enabled keys can be used for cryptographic operations.
	Enabled KeyStatus = iota
	// Disabled keys can't be used, but can be re-enabled.
	Disabled
	// Destroyed keys don't exist in the keyset anymore.
	Destroyed

	// DoNotUse is intended to guard from failures that may be caused by future expansions.
	DoNotUse KeyStatus = 20
)

// Entry represents each entry inside a Keyset.
type Entry struct {
	Status         KeyStatus
	KeyID          uint32
	FormatAsString string
}

// KeysetInfo represents a keyset in a certain point in time for the
// purpose of monitoring operations involving cryptographic keys.
type KeysetInfo struct {
	Annotations  map[string]string
	PrimaryKeyID uint32
	Entries      []*Entry
}

// NewKeysetInfo creates a new KeysetInfo.
func NewKeysetInfo(annotations map[string]string, primaryKeyID uint32, entries []*Entry) *KeysetInfo {
	return &KeysetInfo{
		Annotations:  annotations,
		PrimaryKeyID: primaryKeyID,
		Entries:      entries,
	}
}

// Context defines a context for monitoring events, wich includes the
// primitive and API used, and information on the keyset.
type Context struct {
	Primitive   string
	APIFunction string
	KeysetInfo  *KeysetInfo
}

// NewContext creates a new monitoring context.
func NewContext(primitive string, apiFunction string, keysetInfo *KeysetInfo) *Context {
	return &Context{
		Primitive:   primitive,
		APIFunction: apiFunction,
		KeysetInfo:  keysetInfo,
	}
}

// Logger is an interface for logging which can be created through a `Client`.
// monitoring clients are invoked by Tink during cryptographic operations to emit
// certain events.
type Logger interface {
	// Logs a successful use of `keyID` on an input of `numBytes`. Tink primitive
	// wrappers call this method when they  successfully use a key to carry out a
	// primitive method, e.g. aead.Encrypt(). As a consequence, implementations of
	// MonitoringClient should be mindful on the amount of work performed by this
	// method, as this will be called on each cryptographic operation. Implementations
	// of MonitoringClient are responsible to add context to identify, e.g., the
	// primitive and the API function.
	Log(keyID uint32, numBytes int)

	// Logs a failure. Tink calls this method when a cryptographic operation
	// failed, e.g. no key could be found to decrypt a ciphertext. In this
	// case the failure is not associated with a specific key, therefore this
	// method has no arguments. The MonitoringClient implementation is responsible
	// to add context to identify where the failure comes from.
	LogFailure()
}

// Client represents an interface to hold monitoring client context to create a `Logger`.
// A Client is registered with Tink's registry and used by primitives to obtain a `Logger`.
type Client interface {
	NewLogger(context *Context) (Logger, error)
}
