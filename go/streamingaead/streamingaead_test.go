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

package streamingaead_test

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
)

func Example() {
	dir, err := ioutil.TempDir("", "streamingaead")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	var (
		srcFilename = filepath.Join(dir, "plaintext.src")
		ctFilename  = filepath.Join(dir, "ciphertext.bin")
		dstFilename = filepath.Join(dir, "plaintext.dst")
	)

	if err := ioutil.WriteFile(srcFilename, []byte("this data needs to be encrypted"), 0666); err != nil {
		log.Fatal(err)
	}

	kh, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	a, err := streamingaead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	srcFile, err := os.Open(srcFilename)
	if err != nil {
		log.Fatal(err)
	}

	ctFile, err := os.Create(ctFilename)
	if err != nil {
		log.Fatal(err)
	}

	w, err := a.NewEncryptingWriter(ctFile, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	if _, err := io.Copy(w, srcFile); err != nil {
		log.Fatal(err)
	}

	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	if err := ctFile.Close(); err != nil {
		log.Fatal(err)
	}
	if err := srcFile.Close(); err != nil {
		log.Fatal(err)
	}

	// Decrypt encrypted file.

	ctFile, err = os.Open(ctFilename)
	if err != nil {
		log.Fatal(err)
	}

	dstFile, err := os.Create(dstFilename)
	if err != nil {
		log.Fatal(err)
	}

	r, err := a.NewDecryptingReader(ctFile, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	if _, err := io.Copy(dstFile, r); err != nil {
		log.Fatal(err)
	}

	if err := dstFile.Close(); err != nil {
		log.Fatal(err)
	}
	if err := ctFile.Close(); err != nil {
		log.Fatal(err)
	}

	b, err := ioutil.ReadFile(dstFilename)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
	// Output: this data needs to be encrypted
}

func Example_keyexport() {
	// Create a master key which will be used to export/import streaming GCM HKDF key.
	mkh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}
	masterKey, err := aead.New(mkh)
	if err != nil {
		log.Fatal(err)
	}

	// Create a streaming GCM HDKF key.
	kh, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	a, err := streamingaead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt data using writer.
	buf := &bytes.Buffer{}
	w, err := a.NewEncryptingWriter(buf, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	if _, err := w.Write([]byte("this data needs to be encrypted")); err != nil {
		log.Fatal(err)
	}
	// The writer must be closed!
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	// Export the streaming GCM HKDF key.
	// An io.Reader and io.Writer implementation which simply writes to memory.
	memKeyset := &keyset.MemReaderWriter{}
	if err := kh.Write(memKeyset, masterKey); err != nil {
		log.Fatal(err)
	}

	// Import streaming GCM HKDF key.
	kh, err = keyset.Read(memKeyset, masterKey)
	if err != nil {
		log.Fatal(err)
	}

	a, err = streamingaead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt the data using imported key.
	r, err := a.NewDecryptingReader(buf, []byte("associated data"))
	if err != nil {
		log.Fatal(err)
	}

	got := make([]byte, 256)
	n, err := io.ReadFull(r, got)
	if err != nil && err != io.ErrUnexpectedEOF {
		log.Fatal(err)
	}

	fmt.Println(string(got[:n]))
	// Output: this data needs to be encrypted
}
