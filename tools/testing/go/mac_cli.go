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

// A command-line utility for testing Mac-primitives.
// It requires 4 for MAC computation and 5 for MAC verification:
//   keyset-file:  name of the file with the keyset to be used for MAC
//   operation: the actual MAC-operation, i.e. "compute" or "verify"
//   data-file:  name of the file with data for MAC computation/verification
//   mac-file:  name of the file for MAC value (when computing the MAC),
//              or with MAC value (when verifying the MAC)
//   result-file: name of the file for MAC verification result (valid/invalid)
//                (only for MAC verification operation)
package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
)

func main() {
	if len(os.Args) != 5 && len(os.Args) != 6 {
		log.Fatalf("Usage: %s keyset-file operation data-file mac-file [result-file]\n", os.Args[0])
	}

	keysetFilename := os.Args[1]
	operation := os.Args[2]
	dataFilename := os.Args[3]
	macFilename := os.Args[4]
	resultFilename := ""
	if len(os.Args) == 6 {
		resultFilename = os.Args[5]
	}

	if !(operation == "compute" || operation == "verify") {
		log.Fatalf("Unknown operation %q. Expected 'compute' or 'verify'", operation)
	}

	if operation == "compute" {
		log.Printf("Using keyset from file %q to compute MAC of data from file %q. The resulting MAC will be written to file %q.\n",
			keysetFilename, dataFilename, macFilename)
	} else {
		log.Printf("Using keyset from file %q to verify MAC value from file %q computed for data from file %q. The verification result will be written to file %q.\n",
			keysetFilename, macFilename, dataFilename, resultFilename)
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
	m, err := mac.New(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read input
	content, err := ioutil.ReadFile(dataFilename)
	if err != nil {
		log.Fatalf("Failed to read input: %v", err)
	}

	// Compute output
	var result []byte
	if operation == "compute" {
		result, err = m.ComputeMAC(content)
		if err != nil {
			log.Fatalf("Failed to compute MAC: %v\n", err)
		}
		resultFilename = macFilename
	} else if operation == "verify" {
		log.Println("Verifying MAC...")

		// Read MAC value
		macValue, err := ioutil.ReadFile(macFilename)
		if err != nil {
			log.Fatalf("Failed to read MAC value: %v", err)
		}

		result = []byte("valid")
		err = m.VerifyMAC(macValue, content)
		if err != nil {
			log.Printf("Failed to verify MAC: %v", err)
			result = []byte("invalid")
		}
	}

	// Write to output file
	if err = ioutil.WriteFile(resultFilename, result, 0644); err != nil {
		log.Fatalf("Failed to write result to output file. Error: %v", err)
	}
}
