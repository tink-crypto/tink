// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

package hpke

// hpkeKdf is a package-internal interface for the Hybrid Public Key Encryption
// (HPKE) key derivation function (KDF).
//
// The HPKE I-D is available at
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html.
type hpkeKdf interface {
	// labeledExtract extracts a pseudorandom key from salt, ikm using the
	// HPKE-specified values suiteID, ikmLabel to facilitate domain separation
	// and context binding.
	//
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-4-9
	labeledExtract(salt, ikm []byte, ikmLabel string, suiteID []byte) []byte

	// labeledExpand expands the pseudorandom key prk into length pseudorandom
	// bytes using info with other HPKE-specific values infoLabel, suiteID to
	// facilitate domain separation and context binding.
	//
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-4-9
	labeledExpand(prk, info []byte, infoLabel string, suiteID []byte, length int) ([]byte, error)

	// extractAndExpand calls labeledExtract and labeledExpand in order.
	//
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#section-4.1-3
	extractAndExpand(salt, ikm []byte, ikmLabel string, info []byte, infoLabel string, suiteID []byte, length int) ([]byte, error)

	// kdfID returns the HPKE KDF algorithm identifier for the underlying KDF
	// implementation.
	//
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-12.html#name-key-derivation-functions-kd
	kdfID() uint16
}
