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

// A command-line utility for testing DAEAD-primitives.
// It requires 5 arguments:
//   keyset-file:  name of the file with the keyset to be used
//                 for encrypting/decrypting
//   operation: the actual DeterminisiticAead-operation, i.e.
//              "encryptdeterministically" or "decryptdeterministically"
//   input-file:  name of the file that contains plaintext to be encrypted or the
//                encrypted text to be decrypted
//   additionaldata-file: name of the file that contains
//                        additional-data used for encryption/decryption
//   output-file:  name of the output file for the resulting encryptedtext
package main

import (
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
)

func main() {
	if len(os.Args) != 6 {
		log.Fatalf("Usage: %s keyset-file input-file additionaldata-file output-file", os.Args[0])
	}

	keysetFilename := os.Args[1]
	operation := os.Args[2]
	ipFilename := os.Args[3]
	adFilename := os.Args[4]
	outputFilename := os.Args[5]

	log.Printf("Using keyset from file %q to %q the data in file %q using additional data from file %q.\nThe encrypted data will be written to file %q\n",
		keysetFilename, operation, ipFilename, adFilename, outputFilename)

	if strings.Compare(operation, "encryptdeterministically") != 0 && strings.Compare(operation, "decryptdeterministically") != 0 {
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
	d, err := daead.New(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read input message
	ip, err := ioutil.ReadFile(ipFilename)
	if err != nil {
		log.Fatalf("Failed to read input file: %v", err)
	}

	// Read additional data
	ad, err := ioutil.ReadFile(adFilename)
	if err != nil {
		log.Fatalf("Failed to read additional data: %v", err)
	}
	var op []byte
	if strings.Compare(operation, "encryptdeterministically") == 0 {
		log.Printf("Encrypting...\n")

		if op, err = d.EncryptDeterministically(ip, ad); err != nil {
			log.Fatalf("Error while encrypting: %v\n", err)
		}
	} else if strings.Compare(operation, "decryptdeterministically") == 0 {
		log.Printf("Decrypting...\n")
		if op, err = d.DecryptDeterministically(ip, ad); err != nil {
			log.Fatalf("Error while decrypting: %v\n", err)
		}
	}
	// Write to output file
	if err := ioutil.WriteFile(outputFilename, op, 0644); err != nil {
		log.Fatalf("Failed to write result to output file. Error: %v", err)
	}
}
