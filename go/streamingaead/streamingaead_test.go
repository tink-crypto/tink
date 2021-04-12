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

package streamingaead_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

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

	// TODO: save the keyset to a safe location. DO NOT hardcode it in source code.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

	// Encrypt file.

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

	aad := []byte("this data needs to be authenticated, but not encrypted")
	w, err := a.NewEncryptingWriter(ctFile, aad)
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

	// Decrypt file.

	ctFile, err = os.Open(ctFilename)
	if err != nil {
		log.Fatal(err)
	}

	dstFile, err := os.Create(dstFilename)
	if err != nil {
		log.Fatal(err)
	}

	r, err := a.NewDecryptingReader(ctFile, aad)
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
