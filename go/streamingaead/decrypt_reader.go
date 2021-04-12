// Copyright 2020 Google LLC
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

package streamingaead

import (
	"bytes"
	"errors"
	"io"

	"github.com/google/tink/go/tink"
)

var (
	_              io.Reader = &decryptReader{}
	errKeyNotFound           = errors.New("no matching key found for the ciphertext in the stream")
)

// decryptReader is a reader that tries to find the right key to decrypt ciphertext from the given primitive set.
type decryptReader struct {
	wrapped *wrappedStreamingAEAD
	// cr is a source Reader which provides ciphertext to be decrypted.
	cr  io.Reader
	aad []byte

	matchAttempted bool
	// mr is a matched decrypting reader initialized with a proper key to decrypt ciphertext.
	mr io.Reader
}

func (dr *decryptReader) Read(p []byte) (n int, err error) {
	if dr.mr != nil {
		return dr.mr.Read(p)
	}
	if dr.matchAttempted {
		return 0, errKeyNotFound
	}

	entries, err := dr.wrapped.ps.RawEntries()
	if err != nil {
		return 0, err
	}

	dr.matchAttempted = true
	cr := dr.cr

	// find proper key to decrypt ciphertext
	for _, e := range entries {
		sa, ok := e.Primitive.(tink.StreamingAEAD)
		if !ok {
			continue
		}

		var buf bytes.Buffer
		tee := io.TeeReader(cr, &buf)

		read := func() (io.Reader, int, error) {
			r, err := sa.NewDecryptingReader(tee, dr.aad)
			if err != nil {
				return nil, 0, err
			}
			n, err := r.Read(p)
			if err != nil {
				return nil, 0, err
			}
			return r, n, nil
		}

		r, n, err := read()
		if err == nil {
			dr.mr = r
			return n, nil
		}

		cr = io.MultiReader(&buf, cr)
	}
	return 0, errKeyNotFound
}
