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

import tinkpb "github.com/google/tink/proto/tink_go_proto"

// MemKeyset implements KeysetReader and KeysetWriter for
// *tinkpb.Keyset and *tinkpb.EncryptedKeyset
type MemKeyset struct {
	Keyset          *tinkpb.Keyset
	EncryptedKeyset *tinkpb.EncryptedKeyset
}

// MemKeyset implements KeysetReader
var _ KeysetReader = &MemKeyset{}
var _ KeysetWriter = &MemKeyset{}

// Read returns *tinkpb.Keyset from memory.
func (m *MemKeyset) Read() (*tinkpb.Keyset, error) {
	return m.Keyset, nil
}

// ReadEncrypted returns *tinkpb.EncryptedKeyset from memory.
func (m *MemKeyset) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	return m.EncryptedKeyset, nil
}

// Write keyset to memory.
func (m *MemKeyset) Write(keyset *tinkpb.Keyset) error {
	m.Keyset = keyset
	return nil
}

// WriteEncrypted keyset to memory.
func (m *MemKeyset) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	m.EncryptedKeyset = keyset
	return nil
}
