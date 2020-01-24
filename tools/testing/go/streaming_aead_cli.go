// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

// streaming_aead_cli is a command-line utility for testing StreamingAEAD-primitives.
// It requires 5 arguments:
//   keyset-file:  name of the file with the keyset to be used for encryption
//   operation: the actual StreamingAEAD-operation, i.e. "encrypt" or "decrypt"
//   input-file:  name of the file with input (plaintext for encryption, or
//                or ciphertext for decryption)
//   associated-data-file:  name of the file containing associated data
//   output-file:  name of the file for the resulting output
package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
)

func main() {
	if len(os.Args) != 6 {
		log.Fatalf("Usage: %s keyset-file input-file additionaldata-file output-file", os.Args[0])
	}

	keysetFilename := os.Args[1]
	operation := os.Args[2]
	inFilename := os.Args[3]
	adFilename := os.Args[4]
	outFilename := os.Args[5]

	log.Printf("Using keyset from file %q to %q the data in file %q using additional data from file %q.\nThe encrypted data will be written to file %q\n",
		keysetFilename, operation, inFilename, adFilename, outFilename)

	if operation != "encrypt" && operation != "decrypt" {
		log.Fatalf("Unknown operation: %q\n", operation)
	}

	// Read the keyset.
	f, err := os.Open(keysetFilename)
	if err != nil {
		log.Fatalf("Opening the keyset file failed: %v\n", err)
	}
	reader := keyset.NewBinaryReader(f)
	handle, err := testkeyset.Read(reader)
	if err != nil {
		log.Fatalf("Reading the keyset failed: %v\n", err)
	}

	// Get Primitive
	a, err := streamingaead.New(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read associated data
	ad, err := ioutil.ReadFile(adFilename)
	if err != nil {
		log.Fatalf("Failed to read additional data: %v", err)
	}

	fin, err := os.Open(inFilename)
	if err != nil {
		log.Fatalf("Failed to open input file: %v", err)
	}
	defer fin.Close()

	fout, err := os.Create(outFilename)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}

	switch operation {
	case "encrypt":
		w, err := a.NewEncryptingWriter(fout, ad)
		if err != nil {
			log.Fatalf("Failed to create encrypt writer: %v", err)
		}
		if _, err := io.Copy(w, fin); err != nil {
			log.Fatalf("Failed to encrypt data: %v", err)
		}
		if err := w.Close(); err != nil {
			log.Fatalf("Failed to close encrypt writer: %v", err)
		}
	case "decrypt":
		r, err := a.NewDecryptingReader(fin, ad)
		if err != nil {
			log.Fatalf("Failed to create decrypt reader: %v", err)
		}
		if _, err := io.Copy(fout, r); err != nil {
			log.Fatalf("Failed to encrypt data: %v", err)
		}
	}

	if err := fout.Close(); err != nil {
		log.Fatalf("Failed to close output file: %v", err)
	}
}
