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

// A command-line utility for testing PublicKeySign-primitives.
// It requires 3 arguments:
//   keyset-file:  name of the file with the keyset to be used for signing
//   message-file:  name of the file that contains message to be signed
//   output-file:  name of the output file for the resulting plaintext
package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s keyset-file message-file output-file", os.Args[0])
	}

	keysetFilename := os.Args[1]
	messageFilename := os.Args[2]
	outputFilename := os.Args[3]

	log.Printf("Using keyset from file %q to sign message in file %q.\nThe signature will be written to file %q\n",
		keysetFilename, messageFilename, outputFilename)

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
	signer, err := signature.NewSigner(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read message
	data, err := ioutil.ReadFile(messageFilename)
	if err != nil {
		log.Fatalf("Failed to read message: %v", err)
	}

	log.Printf("Signing...\n")
	var result []byte
	if result, err = signer.Sign(data); err != nil {
		log.Fatalf("Error while signing: %v\n", err)
	}

	// Write to output file
	if err := ioutil.WriteFile(outputFilename, result, 0644); err != nil {
		log.Fatalf("Failed to write result to output file. Error: %v", err)
	}
}
