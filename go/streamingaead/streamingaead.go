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

// Package streamingaead provides implementations of the streaming AEAD primitive.
//
// AEAD encryption assures the confidentiality and authenticity of the data. This primitive is CPA secure.
//
// Example:
//
// import (
// 	"io"
// 	"io/ioutil"
// 	"log"
// 	"os"
// 	"path/filepath"
//
// 	"github.com/google/tink/go/aead"
// 	"github.com/google/tink/go/keyset"
// 	"github.com/google/tink/go/streamingaead"
// )
//
// func main() {
// 	dir, err := ioutil.TempDir("", "streamingaead")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer os.RemoveAll(dir)
//
// 	var (
// 		srcFilename = filepath.Join(dir, "plaintext.src")
// 		ctFilename  = filepath.Join(dir, "ciphertext.bin")
// 		dstFilename = filepath.Join(dir, "plaintext.dst")
// 	)
//
// 	if err := ioutil.WriteFile(srcFilename, []byte("this data needs to be encrypted"), 0666); err != nil {
// 		log.Fatal(err)
// 	}
//
// 	kh, err := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	a, err := streamingaead.New(kh)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	srcFile, err := os.Open(srcFilename)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	ctFile, err := os.Create(ctFilename)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	w, err := a.NewEncryptingWriter(ctFile, []byte("associated data"))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	if _, err := io.Copy(w, srcFile); err != nil {
// 		log.Fatal(err)
// 	}
//
// 	if err := w.Close(); err != nil {
// 		log.Fatal(err)
// 	}
//
// 	if err := ctFile.Close(); err != nil {
// 		log.Fatal(err)
// 	}
// 	if err := srcFile.Close(); err != nil {
// 		log.Fatal(err)
// 	}
//
// 	// Decrypt encrypted file.
//
// 	ctFile, err = os.Open(ctFilename)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	dstFile, err := os.Create(dstFilename)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	r, err := a.NewDecryptingReader(ctFile, []byte("associated data"))
// 	if err != nil {
// 		log.Fatal(err)
// 	}
//
// 	if _, err := io.Copy(dstFile, r); err != nil {
// 		log.Fatal(err)
// 	}
//
// 	if err := dstFile.Close(); err != nil {
// 		log.Fatal(err)
// 	}
// 	if err := ctFile.Close(); err != nil {
// 		log.Fatal(err)
// 	}
// }
package streamingaead

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

func init() {
	if err := registry.RegisterKeyManager(&aesGCMHKDFKeyManager{}); err != nil {
		panic(fmt.Sprintf("streamingaead.init() failed: %v", err))
	}
}
