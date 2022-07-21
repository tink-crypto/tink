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
	ur := &unreader{r: dr.cr}

	// find proper key to decrypt ciphertext
	for _, e := range entries {
		sa, ok := e.Primitive.(tink.StreamingAEAD)
		if !ok {
			continue
		}

		read := func() (io.Reader, int, error) {
			r, err := sa.NewDecryptingReader(ur, dr.aad)
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
			ur.disable()
			return n, nil
		}

		ur.unread()
	}
	return 0, errKeyNotFound
}

// unreader wraps a reader and keeps a copy of everything that's read so it can
// be unread and read again. When no additional unreads are needed, the buffer
// can be disabled and the memory released.
type unreader struct {
	r        io.Reader
	buf      []byte
	pos      int
	disabled bool
}

func (u *unreader) Read(buf []byte) (int, error) {
	if len(u.buf) != u.pos {
		n := copy(buf, u.buf[u.pos:])
		u.pos += n
		return n, nil
	}
	n, err := u.r.Read(buf)
	if u.disabled {
		u.buf = nil
		u.pos = 0
	} else {
		u.buf = append(u.buf, buf[:n]...)
		u.pos = len(u.buf)
	}
	return n, err
}

// unread starts the reader over again. A copy of all read data will be returned
// by `Read()` before the wrapped reader is read from again.
func (u *unreader) unread() {
	u.pos = 0
}

// disable ensures the buffer is released for garbage collection once it's no
// longer needed.
func (u *unreader) disable() {
	u.disabled = true
}
