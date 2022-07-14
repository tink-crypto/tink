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

// A command-line utility for testing AEAD-primitives.
// It requires 5 arguments:
//   keyset-file:  name of the file with the keyset to be used for encryption
//   operation: the actual AEAD-operation, i.e. "encrypt" or "decrypt"
//   input-file:  name of the file with input (plaintext for encryption, or
//                or ciphertext for decryption)
//   associated-data-file:  name of the file containing associated data
//   output-file:  name of the file for the resulting output
package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
)

var (
	gcpURI      = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"
	gcpCredFile = filepath.Join(os.Getenv("TEST_SRCDIR"), "tools/testdata/credential.json")
	awsURI      = "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	awsCredFile = filepath.Join(os.Getenv("TEST_SRCDIR"), "tools/testdata/aws/credentials.csv")
)

func init() {
	gcpclient, err := gcpkms.NewClientWithCredentials(gcpURI, gcpCredFile)
	if err != nil {
		log.Fatal(err)
	}
	registry.RegisterKMSClient(gcpclient)

	awsclient, err := awskms.NewClientWithCredentials(awsURI, awsCredFile)
	if err != nil {
		log.Fatal(err)
	}
	registry.RegisterKMSClient(awsclient)
}

func main() {
	if len(os.Args) != 6 {
		log.Fatalf("Usage: %s keyset-file operation input-file associated-data-file output-file\n", os.Args[0])
	}

	keysetFilename := os.Args[1]
	operation := os.Args[2]
	inputFilename := os.Args[3]
	associatedDataFile := os.Args[4]
	outputFilename := os.Args[5]

	if !(operation == "encrypt" || operation == "decrypt") {
		log.Fatalf("Unknown operation %q. Expected 'encrypt' or 'decrypt'", operation)
	}

	log.Printf("Using keyset from file %q to-AEAD-%s file %q with associated data from file %q.",
		keysetFilename, operation, inputFilename, associatedDataFile)
	log.Printf("The result will be written to %q\n", outputFilename)

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
	cipher, err := aead.New(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read input
	content, err := ioutil.ReadFile(inputFilename)
	if err != nil {
		log.Fatalf("Failed to read input: %v", err)
	}

	// Read associated data
	associatedData, err := ioutil.ReadFile(associatedDataFile)
	if err != nil {
		log.Fatalf("Failed to read associated data file: %v", err)
	}

	// Compute output
	var result []byte
	if operation == "encrypt" {
		result, err = cipher.Encrypt(content, associatedData)
	} else if operation == "decrypt" {
		result, err = cipher.Decrypt(content, associatedData)
	}
	if err != nil {
		log.Fatalf("Failed to %s input file. Error: %v", operation, err)
	}

	// Write to output file
	if err := ioutil.WriteFile(outputFilename, result, 0644); err != nil {
		log.Fatalf("Failed to write result to output file. Error: %v", err)
	}
}
