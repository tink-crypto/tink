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

package keyset

import (
	"io"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// JSONReader deserializes a keyset from jsonpb format.
type JSONReader struct {
	r io.Reader
}

// NewJSONReader returns new JSONReader that will read from r.
func NewJSONReader(r io.Reader) *JSONReader {
	return &JSONReader{r: r}
}

// Read parses a (cleartext) keyset from the underlying io.Reader.
func (jkr *JSONReader) Read() (*tinkpb.Keyset, error) {
	keyset := &tinkpb.Keyset{}

	if err := jsonpb.Unmarshal(jkr.r, keyset); err != nil {
		return nil, err
	}
	return keyset, nil
}

// ReadEncrypted parses an EncryptedKeyset from the underlying io.Reader.
func (jkr *JSONReader) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	keyset := &tinkpb.EncryptedKeyset{}

	if err := jsonpb.Unmarshal(jkr.r, keyset); err != nil {
		return nil, err
	}
	return keyset, nil
}

// JSONWriter serializes a keyset into jsonpb format.
type JSONWriter struct {
	w      io.Writer
	Indent string
}

// NewJSONWriter returns a new JSONWriter that will write to w.
func NewJSONWriter(w io.Writer) *JSONWriter {
	return &JSONWriter{w: w}
}

// Write writes the keyset to the underlying io.Writer.
func (jkw *JSONWriter) Write(keyset *tinkpb.Keyset) error {
	return jkw.writeJSON(jkw.w, keyset)
}

// WriteEncrypted writes the encrypted keyset to the underlying io.Writer.
func (jkw *JSONWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	return jkw.writeJSON(jkw.w, keyset)
}

func (jkw *JSONWriter) writeJSON(w io.Writer, msg proto.Message) error {
	m := &jsonpb.Marshaler{Indent: jkw.Indent}
	return m.Marshal(w, msg)
}
