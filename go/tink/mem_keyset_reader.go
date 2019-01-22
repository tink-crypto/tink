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
	"errors"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// MemKeysetReader implements KeysetReader for *tinkpb.Keyset
type MemKeysetReader struct{ Keyset *tinkpb.Keyset }

// MemKeyset implements KeysetReader
var _ KeysetReader = MemKeysetReader{}

// Read returns *tinkpb.Keyset
func (k MemKeysetReader) Read() (*tinkpb.Keyset, error) {
	return k.Keyset, nil
}

// ReadEncrypted is not implemented.
func (k MemKeysetReader) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	return nil, errors.New("not implemented")
}
