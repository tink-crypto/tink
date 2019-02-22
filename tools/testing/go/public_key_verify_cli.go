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

// A command-line utility for testing PublicKeyVerify-primitives.
// It requires 4 arguments:
//   keyset-file:  name of the file with the keyset to be used for verification
//   signature-file:  name of the file that contains the signature
//   message-file:  name of the file that contains message that was signed
//   output-file:  name of the output file for the verification result
//                 (valid/invalid)
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
	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s keyset-file signature-file message-file output-file", os.Args[0])
	}

	keysetFilename := os.Args[1]
	signatureFilename := os.Args[2]
	messageFilename := os.Args[3]
	outputFilename := os.Args[4]

	log.Printf("Using keyset from file %q to verify signature from file %q of the message from file %q.\nThe verification result will be written to file %q\n",
		keysetFilename, signatureFilename, messageFilename, outputFilename)

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
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read message
	data, err := ioutil.ReadFile(messageFilename)
	if err != nil {
		log.Fatalf("Failed to read message: %v", err)
	}

	// Read signature
	sig, err := ioutil.ReadFile(signatureFilename)
	if err != nil {
		log.Fatalf("Failed to read signature: %v", err)
	}

	log.Printf("Verifying...\n")
	result := []byte("valid")
	if err := verifier.Verify(sig, data); err != nil {
		log.Printf("Error while verifying the signature: %v\n", err)
		result = []byte("invalid")
	}

	// Write to output file
	if err := ioutil.WriteFile(outputFilename, result, 0644); err != nil {
		log.Fatalf("Failed to write result to output file. Error: %v", err)
	}
}
