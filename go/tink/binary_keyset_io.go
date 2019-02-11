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
	"io"
	"io/ioutil"

	"github.com/golang/protobuf/proto"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// BinaryKeysetReader deserializes a keyset from binary proto format.
type BinaryKeysetReader struct {
	r io.Reader
}

// NewBinaryKeysetReader returns new BinaryKeysetReader that will read from r.
func NewBinaryKeysetReader(r io.Reader) *BinaryKeysetReader {
	return &BinaryKeysetReader{r: r}
}

// Read parses a (cleartext) keyset from the underlying io.Reader.
func (bkr *BinaryKeysetReader) Read() (*tinkpb.Keyset, error) {
	keyset := &tinkpb.Keyset{}

	if err := read(bkr.r, keyset); err != nil {
		return nil, err
	}
	return keyset, nil
}

// ReadEncrypted parses an EncryptedKeyset from the underlying io.Reader.
func (bkr *BinaryKeysetReader) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	keyset := &tinkpb.EncryptedKeyset{}

	if err := read(bkr.r, keyset); err != nil {
		return nil, err
	}
	return keyset, nil
}

func read(r io.Reader, msg proto.Message) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	return proto.Unmarshal(data, msg)
}

// BinaryKeysetWriter serializes a keyset into binary proto format.
type BinaryKeysetWriter struct {
	w io.Writer
}

// NewBinaryKeysetWriter returns a new BinaryKeysetWriter that will write to w.
func NewBinaryKeysetWriter(w io.Writer) *BinaryKeysetWriter {
	return &BinaryKeysetWriter{w: w}
}

// Write writes the keyset to the underlying io.Writer.
func (bkw *BinaryKeysetWriter) Write(keyset *tinkpb.Keyset) error {
	return write(bkw.w, keyset)
}

// WriteEncrypted writes the encrypted keyset to the underlying io.Writer.
func (bkw *BinaryKeysetWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	return write(bkw.w, keyset)
}

func write(w io.Writer, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}
