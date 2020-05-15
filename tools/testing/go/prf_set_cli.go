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
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/testkeyset"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatalf("Usage: %s keyset-file data-file prf-file output-length\n", os.Args[0])
	}

	keysetFilename := os.Args[1]
	dataFilename := os.Args[2]
	prfFilename := os.Args[3]
	outputLength, err := strconv.Atoi(os.Args[4])
	if err != nil || outputLength < 0 || outputLength >= 1<<32 {
		log.Fatalf("Output length is not a uint32, but %q", os.Args[4])
	}

	log.Printf("Using keyset from file %q to compute PRFs of data from file %q. The resulting PRFs will be written to file %q.\n",
		keysetFilename, dataFilename, prfFilename)

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
	p, err := prf.NewPRFSet(handle)
	if err != nil {
		log.Fatalf("Failed to create primitive: %v\n", err)
	}

	// Read input
	content, err := ioutil.ReadFile(dataFilename)
	if err != nil {
		log.Fatalf("Failed to read input: %v", err)
	}

	// Compute output
	var outputStream bytes.Buffer
	for id, prf := range p.PRFs {
		outputStream.WriteString(strconv.Itoa(int(id)))
		outputStream.WriteString(":")
		r, err := prf.ComputePRF(content, uint32(outputLength))
		if err != nil {
			outputStream.WriteString("--")
		} else {
			outputStream.WriteString(hex.EncodeToString(r))
		}
		outputStream.WriteString("\n")
	}

	// Write to output file
	if err = ioutil.WriteFile(prfFilename, outputStream.Bytes(), 0644); err != nil {
		log.Fatalf("Failed to write result to output file. Error: %v", err)
	}
}
