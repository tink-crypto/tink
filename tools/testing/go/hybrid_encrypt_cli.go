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

// A command-line utility for testing HybridEncrypt-primitives.
// It requires 4 arguments:
//   keyset-file:  name of the file with the keyset to be used for encrypting
//   plaintext-file:  name of the file that contains plaintext to be encrypted
//   contextinfo-file: name of the file that contains contextinfo used for encryption
//   output-file:  name of the output file for the resulting encryptedtext
package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s keyset-file plaintext-file contextinfo-file output-file", os.Args[0])
	}

	keysetFilename := os.Args[1]
	ptFilename := os.Args[2]
	ctFilename := os.Args[3]
	outputFilename := os.Args[4]

	log.Printf("Using keyset from file %q to encrypt the data in file %q using context info from file %q.\nThe encrypted data will be written to file %q\n",
		keysetFilename, ptFilename, ctFilename, outputFilename)

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
	hybrid, err := hybrid.NewHybridEncrypt(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read plaintext message
	pt, err := ioutil.ReadFile(ptFilename)
	if err != nil {
		log.Fatalf("Failed to read plaintext: %v", err)
	}

	// Read context info
	ct, err := ioutil.ReadFile(ctFilename)
	if err != nil {
		log.Fatalf("Failed to read context info: %v", err)
	}

	log.Printf("Encrypting...\n")
	var et []byte
	if et, err = hybrid.Encrypt(pt, ct); err != nil {
		log.Fatalf("Error while encrypting: %v\n", err)
	}

	// Write to output file
	if err := ioutil.WriteFile(outputFilename, et, 0644); err != nil {
		log.Fatalf("Failed to write result to output file. Error: %v", err)
	}
}
