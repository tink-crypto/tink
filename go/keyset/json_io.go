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

package keyset

import (
	"io"
	"io/ioutil"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// JSONReader deserializes a keyset from json format.
type JSONReader struct {
	r io.Reader
	j *protojson.UnmarshalOptions
}

// NewJSONReader returns new JSONReader that will read from r.
func NewJSONReader(r io.Reader) *JSONReader {
	return &JSONReader{
		r: r,
		j: &protojson.UnmarshalOptions{},
	}
}

// Read parses a (cleartext) keyset from the underlying io.Reader.
func (bkr *JSONReader) Read() (*tinkpb.Keyset, error) {
	keyset := &tinkpb.Keyset{}

	if err := bkr.readJSON(bkr.r, keyset); err != nil {
		return nil, err
	}
	return keyset, nil
}

// ReadEncrypted parses an EncryptedKeyset from the underlying io.Reader.
func (bkr *JSONReader) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	keyset := &tinkpb.EncryptedKeyset{}

	if err := bkr.readJSON(bkr.r, keyset); err != nil {
		return nil, err
	}
	return keyset, nil
}

func (bkr *JSONReader) readJSON(r io.Reader, msg proto.Message) error {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	return bkr.j.Unmarshal(b, msg)
}

// JSONWriter serializes a keyset into json format.
type JSONWriter struct {
	w io.Writer
	j *protojson.MarshalOptions
}

// NewJSONWriter returns a new JSONWriter that will write to w.
func NewJSONWriter(w io.Writer) *JSONWriter {
	return &JSONWriter{
		w: w,
		j: &protojson.MarshalOptions{
			EmitUnpopulated: true,
			Indent:          "",
		},
	}
}

// Write writes the keyset to the underlying io.Writer.
func (bkw *JSONWriter) Write(keyset *tinkpb.Keyset) error {
	return bkw.writeJSON(bkw.w, keyset)
}

// WriteEncrypted writes the encrypted keyset to the underlying io.Writer.
func (bkw *JSONWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	return bkw.writeJSON(bkw.w, keyset)
}

func (bkw *JSONWriter) writeJSON(w io.Writer, msg proto.Message) error {
	b, err := bkw.j.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
